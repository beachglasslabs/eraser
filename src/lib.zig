const std = @import("std");
const assert = std.debug.assert;

const util = @import("util.zig");

pub const ErasureCoder = @import("erasure.zig").ErasureCoder;

pub const EncodeDecodeThreadArgs = struct {
    /// Should be a thread-safe allocator
    allocator: std.mem.Allocator,

    cmd_queue_mtx: *std.Thread.Mutex,
    cmd_queue: *EncDecQueue,

    /// Set to `true` atomically to make the
    /// thread stop once the `cmd_queue` is empty.
    must_stop: *std.atomic.Atomic(bool),

    /// List of URIs to bucket storages, for example:
    /// * `https://www.googleapis.com/storage/v1/b/[BUCKET_NAME]`
    /// * `https://[BUCKET_NAME].s3.eu-west-3.amazonaws.com`
    bucket_uris: []const std.Uri,
};

pub fn encodeDecodeThread(args: EncodeDecodeThreadArgs) void {
    var arena_state = std.heap.ArenaAllocator.init(args.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    _ = arena;

    while (true) {
        const node = blk: {
            args.cmd_queue_mtx.lock();
            defer args.cmd_queue_mtx.unlock();

            break :blk args.cmd_queue.pop() orelse {
                if (args.must_stop.load(.Monotonic)) break;
                std.Thread.yield() catch |err| switch (err) {
                    error.SystemCannotYield => {},
                };
                continue;
            };
        };

        switch (node.data) {
            .encode => |*data| {
                defer if (data.close_after) data.file.close();
                data.efh.done.store(.in_progress, .Monotonic);
                std.log.err("(encode) Fake progress", .{});
                data.efh.done.store(.done, .Monotonic);
            },
            .decode => |data| {
                _ = data;
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
    ) std.mem.Allocator.Error!void {
        const node = try self.newNode();
        errdefer self.unUseNode(node);

        node = .{ .data = .{ .encode = undefined } };
        self.queue.append(node);
        const encode = &node.data.encode;

        encode.* = .{
            .file = file,
            .close_after = close_handling == .close_after,
        };
    }
    pub fn queueUriForDecoding(
        self: *EncDecQueue,
        uri: std.Uri,
        output_writer: anytype,
    ) std.mem.Allocator.Error!void {
        _ = output_writer;
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

    var must_stop = std.atomic.Atomic(bool).init(false);
    const th = try std.Thread.spawn(.{}, encodeDecodeThread, .{EncodeDecodeThreadArgs{
        .allocator = std.testing.allocator,
        .cmd_queue_mtx = &queue_mtx,
        .cmd_queue = &queue,

        .must_stop = &must_stop,

        .bucket_uris = &.{
            try std.Uri.parse("https://www.googleapis.com/storage/v1/b/ec1.blocktube.net "),
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
                const efh = try queue.queueFileForEncoding(try std.fs.cwd().openFile("src/main.zig", .{}), .close_after);
                defer efh.releaseTo(&queue);
            },
            'd' => {
                queue_mtx.lock();
                defer queue_mtx.unlock();
                const uri = comptime try std.Uri.parse("foo/bar");
                try queue.queueUriForDecoding(uri);
            },
            else => {},
        }
    }
}
