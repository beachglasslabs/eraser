const std = @import("std");
const erasure = @import("erasure");
const options = @import("build-options");

test erasure {
    const ec = try erasure.Coder(options.Word).init(std.testing.allocator, .{
        .shard_count = options.shard_count,
        .shards_required = options.shards_required,
    });
    defer ec.deinit(std.testing.allocator);

    const code_datas = try std.testing.allocator.alloc(std.ArrayListUnmanaged(u8), ec.shardCount());
    @memset(code_datas, .{});
    defer {
        for (code_datas) |*code| code.deinit(std.testing.allocator);
        std.testing.allocator.free(code_datas);
    }

    for (code_datas) |*cd| try cd.ensureTotalCapacityPrecise(std.testing.allocator, 4096);

    const shard_fb_streams = try std.testing.allocator.alloc(std.io.FixedBufferStream([]const u8), ec.shardsRequired());
    defer std.testing.allocator.free(shard_fb_streams);

    var default_prng = std.rand.DefaultPrng.init(options.seed);
    const random = default_prng.random();

    var file_buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer file_buffer.deinit();

    var decoded_buffer = std.ArrayList(u8).init(std.testing.allocator);
    defer decoded_buffer.deinit();

    for (options.inputs) |path| {
        for (code_datas) |*cd| cd.clearRetainingCapacity();
        file_buffer.clearRetainingCapacity();
        decoded_buffer.clearRetainingCapacity();

        {
            const file = try std.fs.cwd().openFile(path, .{});
            defer file.close();

            const size = (try file.stat()).size;
            try file_buffer.ensureTotalCapacity(size);
            try decoded_buffer.ensureTotalCapacity(size);

            try file.reader().readAllArrayList(&file_buffer, size * 2);
        }
        const expected_output: []const u8 = file_buffer.items;

        { // encode
            var fbs = std.io.fixedBufferStream(expected_output);

            var write_buffer: [4096]u8 = undefined;
            _ = try ec.encodeCtx(
                fbs.reader(),
                struct {
                    allocator: std.mem.Allocator,
                    code_datas: @TypeOf(code_datas),

                    pub inline fn getWriter(this: @This(), idx: u7) std.ArrayListUnmanaged(u8).Writer {
                        return this.code_datas[idx].writer(this.allocator);
                    }
                }{
                    .allocator = std.testing.allocator,
                    .code_datas = code_datas,
                },
                &write_buffer,
            );
        }

        const excluded_shards = ec.sampleExcludedIndexSet(random);

        for (shard_fb_streams, 0..) |*fbs, sub_idx| {
            const real_idx = excluded_shards.absoluteFromExclusiveSubIndex(@intCast(sub_idx));
            fbs.* = std.io.fixedBufferStream(@as([]const u8, code_datas[real_idx].items));
        }

        _ = try ec.decodeCtx(excluded_shards, decoded_buffer.writer(), struct {
            shard_fb_streams: @TypeOf(shard_fb_streams),

            pub inline fn getReader(this: @This(), sub_idx: u7) std.io.FixedBufferStream([]const u8).Reader {
                return this.shard_fb_streams[sub_idx].reader();
            }
        }{ .shard_fb_streams = shard_fb_streams });
        const actual_output = decoded_buffer.items;

        try std.testing.expectEqualSlices(u8, expected_output, actual_output);
    }
}
