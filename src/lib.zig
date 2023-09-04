const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util.zig");

const erasure = @import("erasure.zig");
pub const SensitiveBytes = @import("SensitiveBytes.zig");
pub const SharedQueue = @import("shared_queue.zig").SharedQueue;

pub const ServerInfo = struct {
    shard_size: u7,
    google_cloud: ?GoogleCloud = null,

    pub const GoogleCloud = struct {
        auth_token: SensitiveBytes,
        bucket_names: []const []const u8,
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
        precalculated_digest: ?[Sha256.digest_length]u8,
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
        server_info: ServerInfo,
        requests_buf: []std.http.Client.Request,
        headers_buf: std.http.Headers,
        gc_authorization_str: ?[]const u8,

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
                .server_info = values.server_info,
                .requests_buf = &.{},
                .headers_buf = std.http.Headers.init(allocator),
                .gc_authorization_str = null,

                .must_stop = std.atomic.Atomic(bool).init(false),
                .queue_mtx = .{},
                .queue = undefined,
                .ec = undefined,
                .thread = undefined,
            };

            self.requests_buf = try self.allocator.alloc(std.http.Client.Request, values.server_info.bucketCount());
            errdefer self.allocator.free(self.requests_buf);

            self.headers_buf.owned = false;
            // self.headers.append("Authorization", authorization) catch |err| break :oom err;
            try self.headers_buf.append("Transfer-Encoding", "chunked");
            try self.headers_buf.append("Authorization", "");

            if (values.server_info.google_cloud) |gc| {
                self.gc_authorization_str = try std.fmt.allocPrint(allocator, "Bearer {s}", .{gc.auth_token.getSensitiveSlice()});
            }
            errdefer self.allocator.free(self.gc_authorization_str orelse &.{});

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
            self.allocator.free(self.gc_authorization_str orelse &.{});
            self.headers_buf.deinit();
        }

        pub inline fn uploadFile(
            self: *Self,
            /// Should be a read-enabled file handle; if this call
            /// succeeds, the caller must leave the closing of the
            /// file handle to the `ctx_ptr`.
            file: std.fs.File,
            /// Optionally provide the SHA256 sum digest; if `null`, the
            /// digest will be calculated during upload.
            precalclulated_digest: ?*const [Sha256.digest_length]u8,
            /// A struct/union/enum/opaque pointer implementing
            /// the `UploadCtx` interface.
            ctx_ptr: anytype,
        ) std.mem.Allocator.Error!void {
            const data = UploadCtx.Data{
                .file = file,
                .precalculated_digest = if (precalclulated_digest) |digest| digest.* else null,
            };
            _ = try self.queue.pushValue(self.allocator, UploadCtx.init(data, ctx_ptr));
        }

        fn uploadPipeLineThread(upp: *Self) void {
            var arena_state = std.heap.ArenaAllocator.init(upp.allocator);
            defer arena_state.deinit();
            const arena = arena_state.allocator();

            var client = std.http.Client{
                .allocator = upp.allocator,
            };
            defer client.deinit();

            while (true) {
                for (0..3) |_| {
                    if (arena_state.reset(.retain_capacity)) break;
                } else assert(arena_state.reset(.free_all));

                const up_ctx: *UploadCtx = upp.queue.popBorrowed() orelse {
                    if (upp.must_stop.load(must_stop_load_mo)) break;
                    std.atomic.spinLoopHint();
                    continue;
                };
                defer upp.queue.destroyBorrowed(up_ctx);
                defer up_ctx.close();
                const data = up_ctx.data;

                const file_size = if (data.file.stat()) |stat| 2 * stat.size else |err| @panic(switch (err) {
                    inline else => |e| "Decide how to handle " ++ @errorName(e),
                });

                const file_digest: [Sha256.digest_length]u8 = data.precalculated_digest orelse digest: {
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
                    const authorization = upp.gc_authorization_str.?;

                    assert(upp.headers_buf.getIndices("Authorization").?.len == 1);
                    assert(upp.headers_buf.getIndices("Transfer-Encoding").?.len == 1);
                    upp.headers_buf.list.items[upp.headers_buf.firstIndexOf("Authorization").?].value = authorization;
                    upp.headers_buf.list.items[upp.headers_buf.firstIndexOf("Transfer-Encoding").?].value = "chunked";

                    const headers = upp.headers_buf;

                    for (gc.bucket_names) |bucket_name| {
                        const uri_str = std.fmt.allocPrint(arena, "https://storage.googleapis.com/{[bucket]s}/{[object]s}", .{
                            .bucket = bucket_name,
                            .object = digestBytesToString(file_digest),
                        }) catch |err| switch (err) {
                            error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                        };
                        const uri = std.Uri.parse(uri_str) catch unreachable;

                        const req = client.request(.PUT, uri, headers, .{}) catch |err| switch (err) {
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
                    up_ctx: *UploadCtx,
                    bytes_uploaded: *u64,
                    file_size: u64,

                    const WriterCtx = struct {
                        inner: Inner,
                        up_ctx: *UploadCtx,
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

/// Purely for testing
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .thread_safe = true,
    }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var queue = EncDecQueue{
        .allocator = allocator,
    };
    defer queue.deinit();

    const gc_auth_token = try std.process.getEnvVarOwned(allocator, "ZIG_TEST_GOOGLE_CLOUD_AUTH_KEY");
    defer allocator.free(gc_auth_token);

    const server_info = ServerInfo{
        .google_cloud = .{
            .auth_token = SensitiveBytes.init(gc_auth_token),
            .bucket_names = &[_][]const u8{
                "ec1.blocktube.net",
                "ec2.blocktube.net",
                "ec3.blocktube.net",
                "ec4.blocktube.net",
                "ec5.blocktube.net",
                "ec6.blocktube.net",
            },
        },
        .shard_size = 3,
    };

    var upload_pipeline: UploadPipeLine(u8) = undefined;
    try upload_pipeline.init(allocator, .{
        .queue_capacity = 8,
        .server_info = server_info,
    });
    defer upload_pipeline.deinit(.finish_remaining_uploads);

    var ect_prng = std.rand.DefaultPrng.init(1234);

    var must_stop = std.atomic.Atomic(bool).init(false);
    const th = try std.Thread.spawn(.{}, encodeDecodeThread, .{EncodeDecodeThreadArgs{
        .allocator = allocator,
        .random = ect_prng.random(),

        .cmd_queue = &queue,

        .must_stop = &must_stop,

        .server_info = server_info,
    }});
    defer th.join();
    defer must_stop.store(true, .Monotonic);

    var line_buffer = std.ArrayList(u8).init(allocator);
    defer line_buffer.deinit();

    while (true) {
        line_buffer.clearRetainingCapacity();
        try std.io.getStdIn().reader().streamUntilDelimiter(line_buffer.writer(), '\n', 1 << 21);
        var tokenizer = std.mem.tokenizeAny(u8, line_buffer.items, &std.ascii.whitespace);

        const cmd = tokenizer.next() orelse {
            std.log.err("Missing command", .{});
            continue;
        };
        assert(cmd.len != 0);
        if (std.mem.startsWith(u8, "quit", cmd)) break; // all of "quit", "qui", "qu", "q" are treated the same

        if (std.mem.eql(u8, cmd, "encode")) {
            const input_path = tokenizer.next() orelse continue;

            std.log.err("Queueing file '{s}' for encoding and upload", .{input_path});
            const input = try std.fs.cwd().openFile(input_path, .{});
            errdefer input.close();

            var progress = std.Progress{};
            const root_node = progress.start("Upload", 100);
            root_node.activate();

            const WaitCtx = struct {
                progress: *std.Progress.Node,
                close_re: std.Thread.ResetEvent = .{},

                pub inline fn update(self: *@This(), percentage: u8) void {
                    self.progress.setCompletedItems(percentage);
                    self.progress.context.maybeRefresh();
                }
                pub inline fn close(self: *@This(), file: std.fs.File) void {
                    file.close();
                    self.close_re.set();
                    while (self.close_re.isSet()) {}
                }
            };
            var wait_ctx = WaitCtx{
                .progress = root_node,
            };

            try upload_pipeline.uploadFile(input, null, &wait_ctx);
            wait_ctx.close_re.wait();
            root_node.end();
            wait_ctx.close_re.reset();

            std.log.info("Finished encoding '{s}'", .{input_path});
        } else if (std.mem.eql(u8, cmd, "decode")) {
            const digest_str = tokenizer.next() orelse continue;
            const digest: [Sha256.digest_length]u8 = digestStringToBytes(digest_str) catch |err| {
                std.log.err("|{s}| Invalid digest", .{@errorName(err)});
                continue;
            };

            const wip = try queue.queueFileForDecoding(digest);
            defer queue.releaseDecodedFile(wip);

            const info = wip.wait();
            std.log.err("writing to {s}.out", .{digestBytesToString(digest)});
            try std.fs.cwd().writeFile(&digestBytesToString(digest) ++ ".out".*, info.data);
        }
    }
}

fn digestBytesToString(bytes: [Sha256.digest_length]u8) [Sha256.digest_length * 2]u8 {
    return std.fmt.bytesToHex(bytes, .lower);
}
fn digestStringToBytes(str: []const u8) error{ InvalidDigestLength, InvalidCharacter }![Sha256.digest_length]u8 {
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
