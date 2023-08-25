const std = @import("std");
const assert = std.debug.assert;

const util = @import("util.zig");

pub inline fn sensitiveBytes(slice: []const u8) SensitiveBytes {
    return .{ .pointer = slice.ptr, .length = slice.len };
}
/// Struct to represent a slice of bytes containing sensitive information
/// which should be formatted and inspected with great care.
pub const SensitiveBytes = struct {
    /// using a multi-ptr avoids any introspecting code from easily treating this as a string
    pointer: [*]const u8,
    length: usize,

    pub fn getSensitiveSlice(self: SensitiveBytes) []const u8 {
        return self.pointer[0..self.length];
    }

    pub fn format(
        self: SensitiveBytes,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (!std.mem.eql(u8, fmt_str, "SENSITIVE"))
            @compileError("Cannot format SensitiveBytes without format specifier being 'SENSITIVE'");
        _ = options;
        try writer.writeByteNTimes('*', @max(1, self.length));
    }
};

pub const ErasureCoder = @import("erasure.zig").ErasureCoder;

pub const EncodeDecodeThreadArgs = struct {
    /// Should be a thread-safe allocator
    allocator: std.mem.Allocator,

    cmd_queue_mtx: *std.Thread.Mutex,
    cmd_queue: *EncDecQueue,

    /// Set to `true` atomically to make the
    /// thread stop once the `cmd_queue` is empty.
    must_stop: *std.atomic.Atomic(bool),

    server_info: ServerInfo,
    error_handling_hints: ErrorHandlingHints = .{},

    pub const ServerInfo = struct {
        // google cloud fields
        gcloud_bucket_names: []const []const u8,
        gcloud_auth_token: ?SensitiveBytes,
    };

    pub const ErrorHandlingHints = struct {
        max_oom_retries: u16 = 100,
    };
};

pub fn encodeDecodeThread(args: EncodeDecodeThreadArgs) void {
    const allocator = args.allocator;

    const queue_mtx = args.cmd_queue_mtx;
    const queue = args.cmd_queue;

    const must_stop = args.must_stop;

    const server_info = args.server_info;
    const err_handling_hints = args.error_handling_hints;
    _ = err_handling_hints;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var client = std.http.Client{
        .allocator = allocator,
    };
    defer client.deinit();

    const string_lt_ctx = struct {
        fn lessThan(_: @This(), lhs: []const u8, rhs: []const u8) bool {
            return std.mem.lessThan(u8, lhs, rhs);
        }
    };
    const longest_gcloud_bucket_name = std.sort.max(
        []const u8,
        args.server_info.gcloud_bucket_names,
        string_lt_ctx{},
        string_lt_ctx.lessThan,
    ) orelse "";

    while (true) {
        // attempt to reset the arena 3 times, otherwise just free
        // the whole thing and allocatea new
        for (0..3) |_| {
            if (arena_state.reset(.retain_capacity)) break;
        } else assert(arena_state.reset(.free_all));

        const node = blk: {
            queue_mtx.lock();
            defer queue_mtx.unlock();

            break :blk queue.pop() orelse {
                if (must_stop.load(.Monotonic)) break;
                std.Thread.yield() catch |err| switch (err) {
                    error.SystemCannotYield => {},
                };
                continue;
            };
        };

        var ec = ErasureCoder(u32).init(arena, @intCast(server_info.gcloud_bucket_names.len), 3) catch |err| switch (err) {
            error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
            inline //
            error.InvalidNumber,
            error.InvalidExponent,
            error.NoInverse,
            => |e| @panic("TODO: decide how to handle '" ++ @errorName(e) ++ "'"),
        };
        defer ec.deinit(arena);

        switch (node.data) {
            .encode => |*data| {
                defer if (data.close_after) data.file.close();

                const ReqWriter = std.http.Client.Request.Writer;
                const ReqAndWriter = struct {
                    request: std.http.Client.Request,
                    writer: ReqWriter,
                };
                var requests_and_writers = std.MultiArrayList(ReqAndWriter){};

                if (server_info.gcloud_auth_token) |auth_token| (oom: {
                    const authorization = std.fmt.allocPrint(arena, "Bearer: {s}", .{
                        auth_token.getSensitiveSlice(),
                    }) catch |err| break :oom err;

                    var headers = std.http.Headers.init(arena);
                    headers.owned = false;
                    headers.append("Authorization", authorization) catch |err| break :oom err;

                    const url_fmt_str = "https://storage.googleapis.com/storage/v1/b/{s}/{s}";
                    const url_buf = arena.alloc(u8, std.fmt.count(url_fmt_str, .{ longest_gcloud_bucket_name, data.name }) +| 10) catch |err| break :oom err;

                    for (server_info.gcloud_bucket_names) |bucket_name| {
                        const url = std.fmt.bufPrint(url_buf, url_fmt_str, .{ bucket_name, data.name }) catch |err| switch (err) {
                            error.NoSpaceLeft => unreachable,
                        };

                        const uri = std.Uri.parse(url) catch |err| switch (err) {
                            inline else => |e| @panic(@errorName(e) ++ " should be unreachable, but was encountered while parsing google cloud bucket URL"),
                        };

                        const req = client.request(.PUT, uri, headers, .{}) catch |err| switch (err) {
                            error.OutOfMemory => |e| break :oom e,
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        requests_and_writers.append(arena, .{
                            .request = req,
                            .writer = undefined,
                        }) catch |err| break :oom err;
                    }
                }) catch |err| switch (err) {
                    error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                };

                const req_and_writers = requests_and_writers.slice();
                const requests: []std.http.Client.Request = req_and_writers.items(.request);
                const writers: []ReqWriter = req_and_writers.items(.writer);

                for (requests) |*req| req.start() catch |err| @panic(switch (err) {
                    inline else => |e| "Decide how to handle " ++ @errorName(e),
                });

                for (writers, requests) |*w, *r| w.* = r.writer();

                _ = ec.encode(arena, data.file.reader(), @as([]const ReqWriter, writers)) catch |err| switch (err) {
                    error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                    inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                };

                for (requests) |*req| req.finish() catch |err| @panic(switch (err) {
                    inline else => |e| "Decide how to handle " ++ @errorName(e),
                });
                for (requests) |*req| {
                    req.wait() catch |err| switch (err) {
                        error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                    std.debug.print("Response from '{s}':\n{}\n", .{ req.uri, req.response.headers });
                    const DebugResponseFmt = struct {
                        reader: std.http.Client.Request.Reader,

                        pub fn format(
                            this: @This(),
                            comptime fmt_str: []const u8,
                            options: std.fmt.FormatOptions,
                            writer: anytype,
                        ) !void {
                            _ = options;
                            _ = fmt_str;
                            var fifo = std.fifo.LinearFifo(u8, .{ .Static = 4096 }).init();
                            fifo.pump(this.reader, writer) catch unreachable;
                        }
                    };
                    std.debug.print("{}", .{DebugResponseFmt{ .reader = req.reader() }});
                }
            },
            .decode => |data| {
                _ = data;
                @panic("TODO: implement decoding requests");
            },
        }
    }
}

pub const EncDecQueue = struct {
    allocator: std.mem.Allocator,
    queue: CmdTailQueue = .{},
    nodes: CmdList = .{},
    nodes_unused: std.ArrayListUnmanaged(*CmdTailQueue.Node) = .{},

    pub fn init(allocator: std.mem.Allocator) EncDecQueue {
        return .{
            .allocator = allocator,
        };
    }
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
        /// TODO: remove this and come up with a better solution for naming the resulting object files
        name: []const u8,
    ) std.mem.Allocator.Error!void {
        const node = try self.newNode();
        errdefer self.unUseNode(node);

        node.* = .{ .data = .{ .encode = undefined } };
        self.queue.append(node);
        const encode = &node.data.encode;

        encode.* = .{
            .file = file,
            .close_after = close_handling == .close_after,
            .name = name,
        };
    }
    pub fn queueUriForDecoding(
        self: *EncDecQueue,
        uri: std.Uri,
    ) std.mem.Allocator.Error!void {
        const node = try self.newNode();
        errdefer self.unUseNode(node);

        node.* = .{ .data = .{ .decode = undefined } };
        self.queue.append(node);
        const decode = &node.data.decode;

        decode.* = .{
            .uri = uri,
        };
    }

    inline fn newNode(self: *EncDecQueue) std.mem.Allocator.Error!*CmdTailQueue.Node {
        if (self.nodes_unused.popOrNull()) |ptr| return ptr;
        try self.nodes_unused.ensureUnusedCapacity(self.allocator, 1);
        const ptr = try self.nodes.addOne(self.allocator);
        return ptr;
    }
    /// `ptr` should be the result of a call to `newNode`.
    inline fn unUseNode(self: *EncDecQueue, ptr: *CmdTailQueue.Node) void {
        // before a new node is created in `newNode`, we
        // reserve capacity for another element in this list,
        // so assuming this `ptr` came from `newNode` (which
        // it always should), this is safe and correct.
        self.nodes_unused.appendAssumeCapacity(ptr);
    }

    fn pop(self: *EncDecQueue) ?*CmdTailQueue.Node {
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
            name: []const u8,
        };
        const Decode = struct {
            uri: std.Uri,
        };
    };
};

test {
    var queue_mtx = std.Thread.Mutex{};
    var queue = EncDecQueue.init(std.testing.allocator);
    defer queue.deinit();

    const gc_auth_token = try std.process.getEnvVarOwned(std.testing.allocator, "ZIG_TEST_GOOGLE_CLOUD_AUTH_KEY");
    defer std.testing.allocator.free(gc_auth_token);

    var must_stop = std.atomic.Atomic(bool).init(false);
    const th = try std.Thread.spawn(.{}, encodeDecodeThread, .{EncodeDecodeThreadArgs{
        .allocator = std.testing.allocator,

        .cmd_queue_mtx = &queue_mtx,
        .cmd_queue = &queue,

        .must_stop = &must_stop,

        .server_info = .{
            .gcloud_bucket_names = &[_][]const u8{
                "ec1.blocktube.net",
                "ec2.blocktube.net",
                "ec3.blocktube.net",
                "ec4.blocktube.net",
                "ec5.blocktube.net",
                "ec6.blocktube.net",
            },
            .gcloud_auth_token = sensitiveBytes(gc_auth_token),
        },
    }});
    defer th.join();
    defer must_stop.store(true, .Monotonic);

    while (true) {
        switch (try std.io.getStdIn().reader().readByte()) {
            'q' => return,
            'e' => {
                queue_mtx.lock();
                defer queue_mtx.unlock();
                try queue.queueFileForEncoding(try std.fs.cwd().openFile("src/main.zig", .{}), .close_after, "src/main.zig");
            },
            'd' => {
                queue_mtx.lock();
                defer queue_mtx.unlock();

                const uri = try std.Uri.parse("foo/bar");
                try queue.queueUriForDecoding(uri);
            },
            else => {},
        }
    }
}
