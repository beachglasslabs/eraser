const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util.zig");

const erasure = @import("erasure.zig");
pub const SensitiveBytes = @import("SensitiveBytes.zig");
pub const SharedQueue = @import("shared_queue.zig").SharedQueue;

pub const ServerInfo = struct {
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
    file: std.fs.File,

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
        self.actionFn(self.ptr, .{ .close = self.file });
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
        must_stop: std.atomic.Atomic(bool),
        queue_mtx: std.Thread.Mutex,
        queue: SharedQueue(UploadCtx),

        server_info: ServerInfo,
        ec: ErasureCoder,
        thread: std.Thread,
        const Self = @This();

        const ErasureCoder = erasure.Coder(W);

        pub fn init(
            /// contents will be entirely oerwritten
            self: *Self,
            /// should be a thread-safe allocator
            allocator: std.mem.Allocator,
            values: struct {
                queue_capacity: usize,
                server_info: ServerInfo,
            },
        ) std.mem.Allocator.Error!void {
            self.* = .{
                .allocator = allocator,
                .must_stop = std.atomic.Atomic(bool).init(false),
                .queue_mtx = .{},
                .queue = undefined,
                .ec = undefined,
                .thread = undefined,
            };

            self.queue = try SharedQueue(UploadCtx).initCapacity(&self.queue_mtx, self.allocator, values.queue_capacity);
            errdefer self.queue.deinit(self.allocator);

            assert(values.server_info.bucketCount() == 6); // TODO: remove this and calculate or add a way to specify the shard size
            self.ec = try ErasureCoder.init(self.allocator, @intCast(values.server_info.bucketCount()), 3);
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
            self.must_stop.store(true, .Monotonic);
            switch (remaining_queue_fate) {
                .finish_remaining_uploads => {},
                .cancel_remaining_uploads => self.queue.clearItems(),
            }
            self.thread.join();
            self.queue.deinit(self.allocator);
        }

        pub inline fn uploadFile(
            self: *Self,
            /// Should be a read-enabled file handle; if this call
            /// succeeds, the caller must leave the closing of the
            /// file handle to the `ctx_ptr`.
            file: std.fs.File,
            /// A struct/union/enum/opaque pointer implementing
            /// the `UploadCtx` interface.
            ctx_ptr: anytype,
        ) std.mem.Allocator.Error!void {
            _ = try self.queue.pushValue(self.allocator, UploadCtx{
                .ptr = ctx_ptr,
                .actionFn = struct {
                    fn actionFn(ptr: *anyopaque, action: UploadCtx.Action) void {
                        const Ptr = @TypeOf(ctx_ptr);
                        const ctx: Ptr = @ptrCast(@alignCast(ptr));
                        switch (action) {
                            .update => |percentage| ctx.update(percentage),
                            .close => |fd| ctx.close(fd),
                        }
                    }
                }.actionFn,
                .file = file,
            });
        }

        fn uploadPipeLineThread(upp: *Self) void {
            while (true) {
                const upload_ctx: *UploadCtx = upp.queue.popBorrowed() orelse {
                    // TODO: should this use a more strict memory order?
                    if (upp.must_stop.load(.Monotonic)) break;
                    std.atomic.spinLoopHint();
                    continue;
                };
                defer upp.queue.destroyBorrowed(upload_ctx);
                errdefer upload_ctx.close();
                @panic("TODO");
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

    assert(server_info.bucketCount() == 6);

    var ec: erasure.Coder(u32) = blk: {
        var retry_count: u16 = 0;
        while (true) break :blk erasure.Coder(u32).init(allocator, @intCast(server_info.bucketCount()), 3) catch |err| switch (err) {
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

        switch (node.data) {
            .encode => |*data| {
                defer if (data.close_after) data.file.close();

                const file_digest: [Sha256.digest_length]u8 = digest: {
                    const Sha256HasherReader = struct {
                        hasher: *Sha256,
                        inner: Inner,
                        const Self = @This();

                        const Inner = std.fs.File.Reader;

                        const Reader = std.io.Reader(Self, Inner.Error, Self.read);
                        fn reader(self: Self) Reader {
                            return .{ .context = self };
                        }
                        fn read(self: Self, buf: []u8) Inner.Error!usize {
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

                var requests = std.ArrayList(std.http.Client.Request).init(arena);
                defer for (requests.items) |*req| req.deinit();

                if (server_info.google_cloud) |gc| (oom: {
                    const authorization = std.fmt.allocPrint(arena, "Bearer {s}", .{gc.auth_token.getSensitiveSlice()}) catch |err| break :oom err;

                    var headers = std.http.Headers.init(arena);
                    headers.owned = false;
                    headers.append("Authorization", authorization) catch |err| break :oom err;
                    headers.append("Transfer-Encoding", "chunked") catch |err| break :oom err;

                    for (gc.bucket_names) |bucket_name| {
                        const uri_str = std.fmt.allocPrint(arena, "https://storage.googleapis.com/{[bucket]s}/{[object]s}", .{
                            .bucket = bucket_name,
                            .object = std.fmt.bytesToHex(file_digest, .lower),
                        }) catch |err| break :oom err;
                        const uri = std.Uri.parse(uri_str) catch unreachable;

                        const req = client.request(.PUT, uri, headers, .{}) catch |err| switch (err) {
                            error.OutOfMemory => |e| break :oom e,
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        requests.append(req) catch |err| break :oom err;
                    }
                }) catch |err| switch (err) {
                    error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                };

                for (requests.items) |*req| req.start() catch |err| @panic(switch (err) {
                    inline else => |e| "Decide how to handle " ++ @errorName(e),
                });

                const WritersCtx = struct {
                    requests: []std.http.Client.Request,

                    pub inline fn getWriter(ctx: @This(), idx: u7) std.http.Client.Request.Writer {
                        return ctx.requests[idx].writer();
                    }
                };

                var buffered = std.io.bufferedReader(data.file.reader());
                _ = ec.encodeCtx(buffered.reader(), WritersCtx{ .requests = requests.items }) catch |err| switch (err) {
                    inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                };

                for (requests.items) |*req| req.finish() catch |err| @panic(switch (err) {
                    inline else => |e| "Decide how to handle " ++ @errorName(e),
                });
                for (requests.items) |*req| {
                    req.wait() catch |err| switch (err) {
                        error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                }

                data.wip.encoded_file = .{
                    .digest = file_digest,
                };
                data.wip.reset_event.set();
            },
            .decode => |*data| {
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
                            .object = std.fmt.bytesToHex(data.digest, .lower),
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
            },
        }
    }
}

pub const EncodedFile = struct {
    digest: [std.crypto.hash.sha2.Sha256.digest_length]u8,

    pub const Wip = struct {
        reset_event: std.Thread.ResetEvent = .{},
        encoded_file: ?EncodedFile = null,

        pub fn wait(wip: *Wip) EncodedFile {
            wip.reset_event.wait();
            return wip.encoded_file.?;
        }
    };
};
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

    pub fn queueFileForEncoding(
        self: *EncDecQueue,
        file: std.fs.File,
        /// Whether or not the file handle should be closed after it has been encoded
        close_handling: enum { close_after, dont_close },
    ) std.mem.Allocator.Error!*EncodedFile.Wip {
        self.mutex.lock();
        defer self.mutex.unlock();

        const node = try self.newNode();
        errdefer self.unUseNode(node);

        node.* = .{ .data = .{ .encode = undefined } };
        self.queue.append(node);
        const encode = &node.data.encode;

        encode.* = .{
            .file = file,
            .close_after = close_handling == .close_after,
            .wip = .{},
        };

        return &encode.wip;
    }

    pub fn releaseEncodedFile(
        self: *EncDecQueue,
        wip: *EncodedFile.Wip,
    ) void {
        self.mutex.lock();
        defer self.mutex.unlock();

        const encode = @fieldParentPtr(CmdQueueItem.Encode, "wip", wip);
        const data = @fieldParentPtr(CmdQueueItem, "encode", encode);
        const node = @fieldParentPtr(CmdTailQueue.Node, "data", data);

        self.unUseNode(node);
    }

    pub fn queueFileForDecoding(
        self: *EncDecQueue,
        digest: [std.crypto.hash.sha2.Sha256.digest_length]u8,
    ) std.mem.Allocator.Error!*DecodedFile.Wip {
        self.mutex.lock();
        defer self.mutex.unlock();

        const node = try self.newNode();
        errdefer self.unUseNode(node);

        node.* = .{ .data = .{ .decode = undefined } };
        self.queue.append(node);
        const decode = &node.data.decode;

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

        const encode = @fieldParentPtr(CmdQueueItem.Decode, "wip", wip);
        const data = @fieldParentPtr(CmdQueueItem, "decode", encode);
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
    const CmdQueueItem = union(enum) {
        encode: Encode,
        decode: Decode,

        const Encode = struct {
            file: std.fs.File,
            close_after: bool,
            wip: EncodedFile.Wip,
        };
        const Decode = struct {
            digest: [std.crypto.hash.sha2.Sha256.digest_length]u8,
            wip: DecodedFile.Wip,
        };
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

    var ect_prng = std.rand.DefaultPrng.init(1234);

    var must_stop = std.atomic.Atomic(bool).init(false);
    const th = try std.Thread.spawn(.{}, encodeDecodeThread, .{EncodeDecodeThreadArgs{
        .allocator = allocator,
        .random = ect_prng.random(),

        .cmd_queue = &queue,

        .must_stop = &must_stop,

        .server_info = .{
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
        },
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

            const wip = try queue.queueFileForEncoding(input, .close_after);
            defer queue.releaseEncodedFile(wip);

            const info = wip.wait();
            std.log.info("Encoded file SHA-256 digest: {s}", .{std.fmt.bytesToHex(info.digest, .lower)});
        } else if (std.mem.eql(u8, cmd, "decode")) {
            const digest_str = tokenizer.next() orelse continue;
            const expected_len = std.crypto.hash.sha2.Sha256.digest_length;
            if (digest_str.len != expected_len * 2) {
                std.log.err("Invalid digest length", .{});
                continue;
            }
            var digest: [expected_len]u8 = undefined;
            assert(digest.len == (std.fmt.hexToBytes(&digest, digest_str) catch unreachable).len);

            const wip = try queue.queueFileForDecoding(digest);
            defer queue.releaseDecodedFile(wip);

            const info = wip.wait();
            std.log.err("writing to {s}.out", .{std.fmt.bytesToHex(digest, .lower)});
            try std.fs.cwd().writeFile(&std.fmt.bytesToHex(digest, .lower) ++ ".out".*, info.data);
        }
    }
}
