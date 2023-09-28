const std = @import("std");
const assert = std.debug.assert;
const eraser = @import("eraser");

pub const std_options = struct {
    pub const log_level: std.log.Level = .debug;
};

pub fn main() !void {
    const log = std.log.default;

    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var default_prng = std.rand.DefaultPrng.init(seed: {
        var seed: u64 = undefined;
        try std.os.getrandom(std.mem.asBytes(&seed));
        break :seed seed;
    });
    const random = default_prng.random();

    var timer = try std.time.Timer.start();

    const argv = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, argv);

    const input = blk: {
        if (argv.len <= 1) {
            log.err("Expected first parameter to be a file argument", .{});
            return error.MissingFileArgument;
        }
        const input_name_str = argv[1];

        break :blk try std.fs.cwd().readFileAlloc(allocator, input_name_str, 1 << 32);
    };
    defer allocator.free(input);

    var encoded: [6]std.ArrayListUnmanaged(u8) = undefined;
    encoded = .{.{}} ** encoded.len;
    defer for (&encoded) |*output| output.deinit(allocator);

    var output_writers: [encoded.len]std.ArrayListUnmanaged(u8).Writer = undefined;
    for (&output_writers, &encoded) |*w, *e| w.* = e.writer(allocator);

    var ec = try eraser.erasure.Coder(u8).init(allocator, .{
        .shard_count = encoded.len,
        .shards_required = 3,
    });
    defer ec.deinit(allocator);

    const encoding_time_ns = blk: {
        var fbs = std.io.fixedBufferStream(input);
        const fbs_reader = fbs.reader();

        timer.reset();
        _ = try ec.encode(fbs_reader, &output_writers);
        const encoding_time_ns = timer.read();
        std.log.info("encoding took {}", .{std.fmt.fmtDuration(encoding_time_ns)});

        break :blk encoding_time_ns;
    };

    var decoded = std.ArrayList(u8).init(allocator);
    defer decoded.deinit();

    const decoding_time_ns = blk: {
        const excluded_set = ec.sampleExcludedIndexSet(random);

        var encoded_fbs: std.BoundedArray(std.io.FixedBufferStream([]const u8), encoded.len) = .{};
        var encoded_readers: std.BoundedArray(std.io.FixedBufferStream([]const u8).Reader, encoded.len) = .{};

        for (&encoded, 0..) |*e, i| {
            if (excluded_set.isSet(@intCast(i))) continue;
            const fbs = encoded_fbs.addOneAssumeCapacity();
            fbs.* = std.io.fixedBufferStream(@as([]const u8, e.items));
            encoded_readers.appendAssumeCapacity(fbs.reader());
        }

        const decoded_writer = decoded.writer();
        const encoded_readers_slice = encoded_readers.constSlice();
        timer.reset();
        _ = try ec.decode(excluded_set, decoded_writer, encoded_readers_slice);
        const decoding_time_ns = timer.read();
        std.log.info("decoding took {}", .{std.fmt.fmtDuration(decoding_time_ns)});

        break :blk decoding_time_ns;
    };

    const enc_dec_order = std.math.order(encoding_time_ns, decoding_time_ns);
    if (enc_dec_order == .eq) {
        std.log.info("Somehow, encoding and decoding took exactly the same time", .{});
        return;
    }

    const fastest: struct { value: u64, name: []const u8 } = switch (enc_dec_order) {
        .eq => unreachable,
        .lt => .{ .value = decoding_time_ns, .name = "Decoding" },
        .gt => .{ .value = encoding_time_ns, .name = "Encoding" },
    };
    const slowest: @TypeOf(fastest) = switch (enc_dec_order) {
        .eq => unreachable,
        .lt => .{ .value = encoding_time_ns, .name = "encoding" },
        .gt => .{ .value = decoding_time_ns, .name = "decoding" },
    };

    var rational = try std.math.big.Rational.init(allocator);
    defer rational.deinit();

    try rational.setRatio(fastest.value, slowest.value);

    const float = try rational.toFloat(f64);
    std.log.info("{s} is {d} times faster than {s}.", .{ fastest.name, float, slowest.name });
}
