const std = @import("std");
const assert = std.debug.assert;

pub const ErasureCoder = @import("erasure.zig").ErasureCoder;

pub const EncDecManager = struct {
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex = .{},
    eraser: ErasureCoder(u32),
    cmd_nodes: CmdList = .{},
    cmd_nodes_unused: std.ArrayListUnmanaged(usize) = .{},
    cmd_queue: CmdQueue = .{},

    running: std.atomic.Atomic(bool) = std.atomic.Atomic(bool).init(true),
    /// read-only after calling `run`
    headers: std.http.Headers,
    const Self = @This();

    const uris = blk: {
        @setEvalBranchQuota(1_000_000);
        break :blk UriList.fromSlice(&.{
            std.Uri.parse("https://storage.googleapis.com/storage/v1/b/ec1.blocktube.net") catch |err| @compileError(@errorName(err)),
            std.Uri.parse("https://storage.googleapis.com/storage/v1/b/ec2.blocktube.net") catch |err| @compileError(@errorName(err)),
            std.Uri.parse("https://storage.googleapis.com/storage/v1/b/ec3.blocktube.net") catch |err| @compileError(@errorName(err)),
            std.Uri.parse("https://storage.googleapis.com/storage/v1/b/ec4.blocktube.net") catch |err| @compileError(@errorName(err)),
            std.Uri.parse("https://storage.googleapis.com/storage/v1/b/ec5.blocktube.net") catch |err| @compileError(@errorName(err)),
        }) catch |err| @compileError(@errorName(err));
    };

    pub const UriList = std.BoundedArray(std.Uri, 5);

    pub fn init(
        /// Should be a thread-safe allocator
        allocator: std.mem.Allocator,
        shard_count: u8,
        shard_size: u8,
    ) !Self {
        var eraser = try ErasureCoder(u32).init(allocator, shard_count, shard_size);
        errdefer eraser.deinit(allocator);

        var headers = std.http.Headers.init(allocator);
        errdefer headers.deinit();

        return EncDecManager{
            .allocator = allocator,
            .eraser = eraser,
            .headers = headers,
        };
    }
    pub fn deinit(self: *Self) void {
        self.headers.deinit();
        self.running.store(false, .Monotonic);
        self.eraser.deinit(self.allocator);
        self.cmd_nodes_unused.deinit(self.allocator);
        self.cmd_nodes.deinit(self.allocator);
    }

    pub fn stop(self: *EncDecManager) void {
        self.running.store(false, .Monotonic);
    }

    /// This should be run in a dedicated thread.
    /// It will attempt to consume all commands in the queue.
    pub fn run(self: *EncDecManager) !void {
        var arena_state = std.heap.ArenaAllocator.init(self.allocator);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        _ = arena;

        while (self.running.load(.Monotonic)) {
            self.mutex.lock();
            const cmd_node: *CmdQueue.Node = self.cmd_queue.popFirst() orelse {
                std.Thread.yield() catch |err| switch (err) {
                    error.SystemCannotYield => {},
                };
                self.mutex.unlock();
                continue;
            };
            self.mutex.unlock();

            // try resetting the arena 3 times at most,
            // otherwise just free it all and start anew.
            for (0..3) |_| {
                if (arena_state.reset(.retain_capacity)) break;
            } else assert(arena_state.reset(.free_all));

            var client = std.http.Client{
                .allocator = arena_state.allocator(),
            };
            defer client.deinit();

            switch (cmd_node.data) {
                .encode => |data| {
                    defer if (data.close_after) data.file.close();
                    const file_stat = try data.file.stat();
                    std.log.err("Need to encode & upload file which is {d} bytes", .{file_stat.size});
                    continue;
                },
                .decode => |data| {
                    std.log.err("Need to download & decode file '{s}'", .{data.uri});
                    continue;
                },
            }
        }
    }

    pub const EncodedFileHandle = struct {};
    pub fn encodeFile(
        self: *Self,
        allocator: std.mem.Allocator,
        file: std.fs.File,
        /// Whether or not the file handle should be closed after it has been encoded
        close_handling: enum { close_after, dont_close },
    ) !*EncodedFileHandle {
        self.mutex.lock();
        defer self.mutex.unlock();

        var should_pop = false;
        const ptr = blk: {
            if (self.cmd_nodes_unused.popOrNull()) |idx| {
                const ptr: *CmdQueue.Node = self.cmd_nodes.at(idx);
                break :blk ptr;
            }
            should_pop = true;
            break :blk try self.cmd_nodes.addOne(allocator);
        };
        errdefer if (should_pop) {
            _ = self.cmd_nodes.pop();
        };

        ptr.* = .{ .data = .{
            .encode = .{
                .file = file,
                .close_after = close_handling == .close_after,
                .efh = .{},
            },
        } };
        self.cmd_queue.append(ptr);
        return &ptr.data.encode.efh;
    }

    const CmdList = std.SegmentedList(CmdQueue.Node, 0);
    const CmdQueue = std.TailQueue(CmdQueueItem);
    const CmdQueueItem = union(enum) {
        encode: Encode,
        decode: Decode,

        const Encode = struct {
            file: std.fs.File,
            close_after: bool,
            efh: EncodedFileHandle,
        };
        const Decode = struct {
            uri: std.Uri,
        };
    };
};

test {
    const allocator = std.testing.allocator;

    var encdecman = try EncDecManager.init(allocator, 5, 3);
    defer encdecman.deinit();

    const th = try std.Thread.spawn(.{}, EncDecManager.run, .{&encdecman});
    defer th.join();

    const file = try std.fs.cwd().openFile("src/main.zig", .{});
    _ = try encdecman.encodeFile(allocator, file, .close_after);

    _ = std.io.getStdIn().reader().readByte() catch {};
    encdecman.stop();
}
