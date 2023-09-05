const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util.zig");

const erasure = @import("erasure.zig");
pub const SensitiveBytes = @import("SensitiveBytes.zig");
pub const SharedQueue = @import("shared_queue.zig").SharedQueue;

pub const chunk_size: comptime_int = 15 * bytes_per_megabyte;
const bytes_per_megabyte = 1e7;

const ChunkCount = std.math.IntFittingRange(1, std.math.maxInt(u64) / chunk_size);
inline fn chunksForFileSize(size: u64) std.math.IntFittingRange(1, std.math.maxInt(u64) / chunk_size) {
    return @intCast(size / chunk_size + 1);
}

pub const ServerInfo = struct {
    shard_size: u7,
    google_cloud: ?GoogleCloud = null,

    pub const GoogleCloud = struct {
        auth_token: SensitiveBytes,
        bucket_names: []const []const u8,

        const authorization_value_fmt = "Bearer {[auth_token]s}";
        const bucket_object_uri_fmt = "https://storage.googleapis.com/{[bucket]s}/{[object]s}";

        fn preAllocated(gc: GoogleCloud, allocator: std.mem.Allocator) std.mem.Allocator.Error!PreAllocated {
            var full_size: usize = 0;
            full_size += std.fmt.count(authorization_value_fmt, .{ .auth_token = gc.auth_token.getSensitiveSlice() });

            for (gc.bucket_names) |bucket_name| {
                const max_digest_str: []const u8 = comptime &digestBytesToString("\xff".* ** Sha256.digest_length);
                full_size += std.fmt.count(bucket_object_uri_fmt, .{
                    .bucket = bucket_name,
                    .object = max_digest_str,
                });
            }

            const full_buf_alloc = try allocator.alloc(u8, full_size);
            errdefer allocator.free(full_buf_alloc);

            const authorization_value = std.fmt.bufPrint(full_buf_alloc, authorization_value_fmt, .{ .auth_token = gc.auth_token.getSensitiveSlice() }) catch unreachable;
            const bucket_uris_buf = full_buf_alloc[authorization_value.len..];

            var headers = std.http.Headers.init(allocator);
            errdefer headers.deinit();
            headers.owned = false;

            try headers.append("Authorization", authorization_value);
            try headers.append("Transfer-Encoding", "chunked");

            return .{
                .full_buf_alloc = full_buf_alloc,
                .authorization_value = authorization_value,
                .bucket_uris_buf = bucket_uris_buf,
                .headers = headers,
            };
        }

        const PreAllocated = struct {
            full_buf_alloc: []u8,
            authorization_value: []const u8,
            bucket_uris_buf: []u8,
            headers: std.http.Headers,

            pub fn deinit(pre_allocated: PreAllocated, allocator: std.mem.Allocator) void {
                allocator.free(pre_allocated.full_buf_alloc);

                var headers_copy = pre_allocated.headers;
                headers_copy.allocator = allocator;
                headers_copy.deinit();
            }

            /// The strings obtained from the returned iterator are valid until the next call to this function.
            pub fn bucketObjectUriIterator(self: PreAllocated, gc: GoogleCloud, object: *const [Sha256.digest_length]u8) BucketObjectUriIterator {
                return .{
                    .bucket_names = gc.bucket_names,
                    .bytes = .{ .buffer = self.bucket_uris_buf },
                    .object = object,
                };
            }

            const BucketObjectUriIterator = struct {
                index: usize = 0,
                bucket_names: []const []const u8,
                bytes: util.BoundedBufferArray(u8),
                object: *const [Sha256.digest_length]u8,

                /// Each string returned is a unique slice which does not overlap with any previously returned slice.
                pub fn next(iter: *BucketObjectUriIterator) ?[]const u8 {
                    if (iter.index == iter.bucket_names.len) return null;
                    const bucket = iter.bucket_names[iter.index];
                    iter.index += 1;

                    const start = iter.bytes.len;
                    iter.bytes.writer().print(bucket_object_uri_fmt, .{
                        .bucket = bucket,
                        .object = iter.object,
                    }) catch |err| switch (err) {
                        error.Overflow => unreachable,
                    };
                    const end = iter.bytes.len;
                    return iter.bytes.slice()[start..end];
                }
            };
        };
    };

    inline fn bucketCount(server_info: ServerInfo) usize {
        var result: usize = 0;
        if (server_info.google_cloud) |gcloud| {
            result += gcloud.bucket_names.len;
        }
        return result;
    }
};

pub const UploadCtx = struct {
    ptr: *anyopaque,
    actionFn: *const fn (ptr: *anyopaque, state: Action) void,
    data: Data,

    pub const Data = struct {
        file: std.fs.File,
        file_size: u64,
        start: u64,
    };

    pub inline fn init(data: Data, ctx_ptr: anytype) UploadCtx {
        const Ptr = @TypeOf(ctx_ptr);
        const gen = struct {
            fn actionFn(erased_ptr: *anyopaque, action: UploadCtx.Action) void {
                const ptr: Ptr = @ptrCast(@alignCast(erased_ptr));
                switch (action) {
                    .update => |percentage| ptr.update(percentage),
                    .close => |fd| ptr.close(fd),
                }
            }
        };
        return .{
            .ptr = ctx_ptr,
            .actionFn = gen.actionFn,
            .data = data,
        };
    }

    /// Informs the context of the percentage of progress.
    pub inline fn update(self: UploadCtx, percentage: u8) void {
        self.actionFn(self.ptr, .{ .update = percentage });
    }

    /// After returns, the `UploadCtx` will be destroyed,
    /// meaning either the file has been fully uploaded,
    /// or the process to upload the file has failed
    /// irrecoverably.
    /// Gives the file handle back to the inner context.
    pub inline fn close(self: UploadCtx) void {
        self.actionFn(self.ptr, .{ .close = self.data.file });
    }

    pub const Action = union(enum) {
        /// percentage of progress
        update: u8,
        /// The upload context is being closed, so the file handle
        /// is returned. The context may store it elsewhere for
        /// further use, or simply close it.
        close: std.fs.File,
    };
};

pub fn UploadPipeLine(comptime W: type) type {
    return struct {
        allocator: std.mem.Allocator,
        requests_buf: []std.http.Client.Request,
        server_info: ServerInfo,
        gc_prealloc: ?ServerInfo.GoogleCloud.PreAllocated,

        must_stop: std.atomic.Atomic(bool),
        queue_mtx: std.Thread.Mutex,
        queue: SharedQueue(UploadCtx),

        ec: ErasureCoder,
        thread: std.Thread,
        const Self = @This();

        const ErasureCoder = erasure.Coder(W);

        // TODO: should this use a more strict memory order?
        const must_stop_store_mo: std.builtin.AtomicOrder = .Monotonic;
        const must_stop_load_mo: std.builtin.AtomicOrder = .Monotonic;

        pub fn init(
            /// contents will be entirely oerwritten
            self: *Self,
            /// should be a thread-safe allocator
            allocator: std.mem.Allocator,
            values: struct {
                queue_capacity: usize,
                server_info: ServerInfo,
            },
        ) (std.mem.Allocator.Error || ErasureCoder.InitError || std.Thread.SpawnError)!void {
            self.* = .{
                .allocator = allocator,
                .requests_buf = &.{},
                .server_info = values.server_info,
                .gc_prealloc = null,

                .must_stop = std.atomic.Atomic(bool).init(false),
                .queue_mtx = .{},
                .queue = undefined,

                .ec = undefined,
                .thread = undefined,
            };

            self.requests_buf = try self.allocator.alloc(std.http.Client.Request, values.server_info.bucketCount());
            errdefer self.allocator.free(self.requests_buf);

            if (values.server_info.google_cloud) |gc| {
                self.gc_prealloc = try gc.preAllocated(self.allocator);
            }
            errdefer if (self.gc_prealloc) |pre_alloc| pre_alloc.deinit(self.allocator);

            self.queue = try SharedQueue(UploadCtx).initCapacity(&self.queue_mtx, self.allocator, values.queue_capacity);
            errdefer self.queue.deinit(self.allocator);

            self.ec = try ErasureCoder.init(self.allocator, @intCast(values.server_info.bucketCount()), values.server_info.shard_size);
            errdefer self.ec.deinit(self.allocator);

            self.thread = try std.Thread.spawn(.{ .allocator = self.allocator }, uploadPipeLineThread, .{self});
        }

        pub fn deinit(
            self: *Self,
            remaining_queue_fate: enum {
                finish_remaining_uploads,
                cancel_remaining_uploads,
            },
        ) void {
            self.must_stop.store(true, must_stop_store_mo);
            switch (remaining_queue_fate) {
                .finish_remaining_uploads => {},
                .cancel_remaining_uploads => self.queue.clearItems(),
            }
            self.thread.join();
            self.queue.deinit(self.allocator);
            self.ec.deinit(self.allocator);
            self.allocator.free(self.requests_buf);
            if (self.gc_prealloc) |pre_alloc| pre_alloc.deinit(self.allocator);
        }

        pub inline fn uploadFile(
            self: *Self,
            /// Should be a read-enabled file handle; if this call
            /// succeeds, the caller must leave the closing of the
            /// file handle to the `ctx_ptr`.
            file: std.fs.File,
            /// A struct/union/enum/opaque pointer implementing
            /// the `UploadCtx` interface.
            /// The pointer must outlive the function call, until
            /// its `close` callback is called.
            ctx_ptr: anytype,
            extra: struct {
                /// Pre-calculated size of the file; if `null`,
                /// the size will be determined during this function call.
                file_size: ?u64 = null,
            },
        ) (std.mem.Allocator.Error || std.fs.File.StatError)!void {
            const file_size: u64 = if (extra.file_size) |size| size else blk: {
                const stat = try file.stat();
                break :blk stat.size;
            };

            const chunk_count: ChunkCount = @intCast((file_size / chunk_size) + 1);

            self.queue.mutex.lock();
            defer self.queue.mutex.unlock();

            var start: u64 = 0;
            for (0..chunk_count) |_| {
                const data = UploadCtx.Data{
                    .file = file,
                    .file_size = file_size,
                    .start = start,
                };
                start += chunk_size;
                _ = self.queue.pushValueAssumeCapacityLocked(UploadCtx.init(data, ctx_ptr));
            }
        }

        fn uploadPipeLineThread(upp: *Self) void {
            var client = std.http.Client{
                .allocator = upp.allocator,
            };
            defer client.deinit();

            while (true) {
                const up_ctx: UploadCtx = upp.queue.popValue() orelse {
                    if (upp.must_stop.load(must_stop_load_mo)) break;
                    std.atomic.spinLoopHint();
                    continue;
                };
                defer up_ctx.close();
                const data = up_ctx.data;

                const file_size = data.file_size;
                if (data.start != 0) {
                    std.log.err("TODO: actually chunk the file", .{});
                    continue;
                }

                const file_digest: [Sha256.digest_length]u8 = digest: {
                    const Sha256HasherReader = struct {
                        hasher: *Sha256,
                        inner: Inner,
                        const Self = @This();

                        const Inner = std.fs.File.Reader;

                        const Reader = std.io.Reader(@This(), Inner.Error, @This().read);
                        fn reader(self: @This()) Reader {
                            return .{ .context = self };
                        }
                        fn read(self: @This(), buf: []u8) Inner.Error!usize {
                            const result = try self.inner.read(buf);
                            self.hasher.update(buf[0..result]);
                            return result;
                        }
                    };
                    var hasher = Sha256.init(.{});
                    const hasher_reader = Sha256HasherReader.reader(.{
                        .hasher = &hasher,
                        .inner = data.file.reader(),
                    });
                    const Fifo = std.fifo.LinearFifo(u8, .{ .Static = 4096 });
                    var fifo: Fifo = Fifo.init();
                    defer fifo.deinit();

                    fifo.pump(hasher_reader, std.io.null_writer) catch |err| @panic(switch (err) {
                        inline else => |e| "Decide how to handle " ++ @errorName(e),
                    });
                    data.file.seekTo(0) catch |err| @panic(switch (err) {
                        inline else => |e| "Decide how to handle " ++ @errorName(e),
                    });

                    break :digest hasher.finalResult();
                };

                var requests = util.BoundedBufferArray(std.http.Client.Request){ .buffer = upp.requests_buf };
                defer for (requests.slice()) |*req| req.deinit();

                if (upp.server_info.google_cloud) |gc| {
                    const gc_prealloc = upp.gc_prealloc.?;
                    var iter = gc_prealloc.bucketObjectUriIterator(gc, &file_digest);

                    while (iter.next()) |uri_str| {
                        const uri = std.Uri.parse(uri_str) catch unreachable;
                        const req = client.request(.PUT, uri, gc_prealloc.headers, .{}) catch |err| switch (err) {
                            error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        requests.appendAssumingCapacity(req);
                    }
                }

                for (requests.slice()) |*req| req.start() catch |err| @panic(switch (err) {
                    inline else => |e| "Decide how to handle " ++ @errorName(e),
                });

                var bytes_uploaded: u64 = 0;
                const WritersCtx = struct {
                    requests: []std.http.Client.Request,
                    up_ctx: UploadCtx,
                    bytes_uploaded: *u64,
                    file_size: u64,

                    const WriterCtx = struct {
                        inner: Inner,
                        up_ctx: UploadCtx,
                        bytes_uploaded: *u64,
                        file_size: u64,

                        const Inner = std.http.Client.Request.Writer;
                        const Error = Inner.Error;
                        fn write(self: @This(), bytes: []const u8) Error!usize {
                            const written = try self.inner.write(bytes);
                            self.bytes_uploaded.* += written;
                            self.up_ctx.update(@intCast((self.bytes_uploaded.* * 100) / self.file_size));
                            return written;
                        }
                    };
                    pub inline fn getWriter(ctx: @This(), idx: u7) std.io.Writer(WriterCtx, WriterCtx.Error, WriterCtx.write) {
                        return .{ .context = .{
                            .inner = ctx.requests[idx].writer(),
                            .up_ctx = ctx.up_ctx,
                            .bytes_uploaded = ctx.bytes_uploaded,
                            .file_size = ctx.file_size,
                        } };
                    }
                };
                const writers_ctx = WritersCtx{
                    .requests = requests.slice(),
                    .up_ctx = up_ctx,
                    .bytes_uploaded = &bytes_uploaded,
                    .file_size = file_size,
                };

                var buffered = std.io.bufferedReader(data.file.reader());
                _ = upp.ec.encodeCtx(buffered.reader(), writers_ctx) catch |err| switch (err) {
                    inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                };

                for (requests.slice()) |*req| req.finish() catch |err| @panic(switch (err) {
                    inline else => |e| "Decide how to handle " ++ @errorName(e),
                });

                for (@as([]std.http.Client.Request, requests.slice())) |*req| {
                    req.wait() catch |err| switch (err) {
                        error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                }
            }
        }
    };
}

pub const EncodeDecodeThreadArgs = struct {
    /// Should be a thread-safe allocator
    allocator: std.mem.Allocator,
    /// Should be a Pseudo-RNG, and be thread-safe (or otherwise guaranteed to only be used by `encodeDecodeThread`).
    random: std.rand.Random,

    cmd_queue: *EncDecQueue,

    /// Set to `true` atomically to make the
    /// thread stop once the `cmd_queue` is empty.
    must_stop: *std.atomic.Atomic(bool),

    server_info: ServerInfo,
    error_handling_hints: ErrorHandlingHints = .{
        .max_oom_retries = 100,
    },

    pub const ErrorHandlingHints = struct {
        max_oom_retries: u16,
    };
};

pub fn encodeDecodeThread(args: EncodeDecodeThreadArgs) void {
    const allocator = args.allocator;
    const random = args.random;

    const queue = args.cmd_queue;

    const must_stop = args.must_stop;

    const server_info = args.server_info;
    const err_handling_hints = args.error_handling_hints;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var client = std.http.Client{
        .allocator = allocator,
    };
    defer client.deinit();

    var ec: erasure.Coder(u8) = blk: {
        var retry_count: u16 = 0;
        while (true) break :blk erasure.Coder(u8).init(allocator, @intCast(server_info.bucketCount()), server_info.shard_size) catch |err| switch (err) {
            error.OutOfMemory => {
                if (retry_count == err_handling_hints.max_oom_retries) @panic("TODO: handle retrying the maximum number of times");
                retry_count += 1;
                continue;
            },

            inline //
            error.InvalidNumber,
            error.InvalidExponent,
            error.NoInverse,
            error.ZeroShards,
            error.ZeroShardSize,
            error.ShardSizePlusCountOverflow,
            => |e| @panic("TODO: decide how to handle '" ++ @errorName(e) ++ "'"),
        };
    };
    defer ec.deinit(allocator);

    while (true) {
        // attempt to reset the arena 3 times, otherwise just free
        // the whole thing and allocatea new
        for (0..3) |_| {
            if (arena_state.reset(.retain_capacity)) break;
        } else assert(arena_state.reset(.free_all));

        const node = blk: {
            break :blk queue.pop() orelse {
                if (must_stop.load(.Monotonic)) break;
                std.Thread.yield() catch |err| switch (err) {
                    error.SystemCannotYield => {},
                };
                continue;
            };
        };

        const data = &node.data;
        const excluded_shards = erasure.sampleIndexSet(
            random,
            ec.shardCount(),
            ec.shardCount() - ec.shardSize(),
        );

        var requests = std.ArrayList(std.http.Client.Request).init(arena);
        defer for (requests.items) |*req| req.deinit();
        var shard_idx: u8 = 0;

        if (server_info.google_cloud) |gc| (oom: {
            const authorization = std.fmt.allocPrint(arena, "Bearer {s}", .{gc.auth_token.getSensitiveSlice()}) catch |err| break :oom err;

            var headers = std.http.Headers.init(arena);
            headers.owned = false;
            headers.append("Authorization", authorization) catch |err| break :oom err;

            for (gc.bucket_names) |bucket_name| {
                {
                    defer shard_idx += 1;
                    if (excluded_shards.isSet(shard_idx)) continue;
                }

                const uri_str = std.fmt.allocPrint(arena, "https://storage.googleapis.com/{[bucket]s}/{[object]s}", .{
                    .bucket = bucket_name,
                    .object = digestBytesToString(data.digest),
                }) catch |err| break :oom err;
                const uri = std.Uri.parse(uri_str) catch unreachable;

                const req = client.request(.GET, uri, headers, .{}) catch |err| switch (err) {
                    error.OutOfMemory => |e| break :oom e,
                    inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                };
                requests.append(req) catch |err| break :oom err;
            }
        }) catch |err| switch (err) {
            error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
        };

        for (requests.items) |*req| {
            req.start() catch |err| @panic(switch (err) {
                inline else => |e| "Decide how to handle " ++ @errorName(e),
            });
            req.finish() catch |err| @panic(switch (err) {
                inline else => |e| "Decide how to handle " ++ @errorName(e),
            });
        }

        for (requests.items) |*req| req.wait() catch |err| @panic(switch (err) {
            inline else => |e| "Decide how to handle " ++ @errorName(e),
        });

        const ReadersCtx = struct {
            requests: []std.http.Client.Request,

            pub fn getReader(ctx: @This(), idx: u7) std.http.Client.Request.Reader {
                return ctx.requests[idx].reader();
            }
        };

        var decoded = std.ArrayList(u8).initCapacity(allocator, 2e8) catch |err| switch (err) {
            error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
        };
        defer decoded.deinit();

        // var buffered = std.io.bufferedWriter(decoded.writer());
        _ = ec.decodeCtx(excluded_shards, decoded.writer(), ReadersCtx{ .requests = requests.items }) catch |err| switch (err) {
            inline else => |e| @panic("TODO: decide how to handle " ++ @errorName(e)),
        };
        // buffered.flush() catch |err| @panic(@errorName(err));

        data.wip.decoded_file = .{
            .data = decoded.toOwnedSlice() catch |err| switch (err) {
                error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
            },
        };
        data.wip.reset_event.set();
    }
}

pub const DecodedFile = struct {
    data: []const u8,

    pub const Wip = struct {
        reset_event: std.Thread.ResetEvent = .{},
        decoded_file: ?DecodedFile = null,

        pub fn wait(wip: *Wip) DecodedFile {
            wip.reset_event.wait();
            return wip.decoded_file.?;
        }
    };
};

pub const EncDecQueue = struct {
    /// Should be a thread-safe allocator
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    queue: CmdTailQueue = .{},
    nodes: CmdList = .{},
    nodes_unused: std.ArrayListUnmanaged(*CmdTailQueue.Node) = .{},

    pub fn deinit(self: *EncDecQueue) void {
        self.nodes_unused.deinit(self.allocator);
        self.nodes.deinit(self.allocator);
        self.queue = .{};
    }

    pub fn queueFileForDecoding(
        self: *EncDecQueue,
        digest: [Sha256.digest_length]u8,
    ) std.mem.Allocator.Error!*DecodedFile.Wip {
        self.mutex.lock();
        defer self.mutex.unlock();

        const node = try self.newNode();
        errdefer self.unUseNode(node);

        node.* = .{ .data = undefined };
        self.queue.append(node);
        const decode = &node.data;

        decode.* = .{
            .digest = digest,
            .wip = .{},
        };
        return &decode.wip;
    }

    pub fn releaseDecodedFile(
        self: *EncDecQueue,
        wip: *DecodedFile.Wip,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const info = wip.wait();
        self.allocator.free(info.data);

        const data = @fieldParentPtr(CmdQueueItem, "wip", wip);
        const node = @fieldParentPtr(CmdTailQueue.Node, "data", data);

        self.unUseNode(node);
    }

    inline fn newNode(self: *EncDecQueue) std.mem.Allocator.Error!*CmdTailQueue.Node {
        if (self.nodes_unused.popOrNull()) |ptr| return ptr;
        try self.nodes_unused.ensureUnusedCapacity(self.allocator, 1);
        const ptr = try self.nodes.addOne(self.allocator);
        return ptr;
    }
    /// `ptr` should be the result of a call to `newNode`.
    inline fn unUseNode(self: *EncDecQueue, ptr: *CmdTailQueue.Node) void {
        ptr.data = undefined;
        // before a new node is created in `newNode`, we
        // reserve capacity for another element in this list,
        // so assuming this `ptr` came from `newNode` (which
        // it always should), this is safe and correct.
        self.nodes_unused.appendAssumeCapacity(ptr);
    }

    inline fn pop(self: *EncDecQueue) ?*CmdTailQueue.Node {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.queue.popFirst();
    }

    const CmdList = std.SegmentedList(CmdTailQueue.Node, 0);
    const CmdTailQueue = std.TailQueue(CmdQueueItem);
    const CmdQueueItem = struct {
        digest: [Sha256.digest_length]u8,
        wip: DecodedFile.Wip,
    };
};

pub fn digestBytesToString(bytes: [Sha256.digest_length]u8) [Sha256.digest_length * 2]u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}
pub fn digestStringToBytes(str: []const u8) error{ InvalidDigestLength, InvalidCharacter }![Sha256.digest_length]u8 {
    if (str.len != Sha256.digest_length * 2)
        return error.InvalidDigestLength;
    var digest = [_]u8{0} ** Sha256.digest_length;
    const digest_slice = std.fmt.hexToBytes(&digest, str) catch |err| switch (err) {
        error.InvalidLength => unreachable,
        error.NoSpaceLeft => unreachable,
        error.InvalidCharacter => |e| return e,
    };
    assert(digest.len == digest_slice.len);
    return digest;
}
