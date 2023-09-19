const std = @import("std");

const galois = @import("galois.zig");
const erasure = @import("erasure.zig");
const Matrix = @import("Matrix.zig");
const BinaryFieldMatrix = @import("BinaryFieldMatrix.zig");

test {
    _ = galois;
    _ = erasure;
    _ = Matrix;
    _ = BinaryFieldMatrix;
    _ = @import("SensitiveBytes.zig");
    _ = @import("pipelines.zig");
}

const usage =
    \\Usage: eraser [command] [options]
    \\
    \\Commands:
    \\
    \\  encode              encode data
    \\  decode              decode data
    \\
    \\General Options:
    \\  -n                  code chunks in a block # default: 5
    \\  -k                  data chunks in a block # default: 3
    \\  -w                  bytes in a word in a chunks (u8|u16|u32|u64) # default: u64
    \\
    \\  --data              name of data fifo file
    \\  --code              prefix of code files
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .thread_safe = true,
    }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const cmds = try parseArgs(args[1..]);
    const data = cmds.data orelse return error.MissingDataFileName;
    const code = cmds.code orelse return error.MissingCodeDirName;

    switch (cmds.w orelse .u64) {
        inline else => |word| {
            const W = switch (word) {
                .u8 => u8,
                .u16 => u16,
                .u32 => u32,
                .u64 => u64,
            };

            switch (cmds.verb) {
                .encode => try encodeCommand(allocator, W, cmds.n orelse 5, cmds.k orelse 3, data, code),
                .decode => try decodeCommand(allocator, W, cmds.n orelse 5, cmds.k orelse 3, data, code),
            }
        },
    }
}

const Args = struct {
    verb: Verb,
    code: ?[]const u8 = null,
    data: ?[]const u8 = null,
    n: ?u7 = null,
    k: ?u7 = null,
    w: ?Word = null,

    const Verb = enum { encode, decode };
    const Word = enum { u8, u16, u32, u64 };
};

fn parseArgs(argv: []const []const u8) !Args {
    errdefer std.log.info("Usage: {s}", .{usage});
    var parsed: Args = .{
        .verb = std.meta.stringToEnum(Args.Verb, @as(?[]const u8, argv[0]) orelse
            return error.MissingVerb) orelse
            return error.UnrecognizedVerb,
    };

    const FieldTag = std.meta.FieldEnum(Args);
    const FieldSet = std.EnumSet(FieldTag);
    var arg_set = FieldSet.initMany(&.{ .verb, .n, .k, .w });

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const Case = enum {
            @"--code",
            @"--data",
            @"-n",
            @"-k",
            @"-w",
        };
        const case = std.meta.stringToEnum(Case, argv[i]) orelse {
            std.log.err("Unrecognized argument '{s}'", .{argv[i]});
            return error.UnrecognizedArgument;
        };
        const field_tag: FieldTag = switch (case) {
            inline .@"--code", .@"--data" => |tag| @field(FieldTag, @tagName(tag)[2..]),
            inline .@"-n", .@"-k", .@"-w" => |tag| @field(FieldTag, @tagName(tag)[1..]),
        };
        arg_set.insert(field_tag);
        i += 1;
        if (i == argv.len) return error.MissingArgumentValue;

        switch (field_tag) {
            .verb => return error.UnrecognizedArgument,
            inline .code, .data => |tag| @field(parsed, @tagName(tag)) = argv[i],
            inline .n, .k => |tag| @field(parsed, @tagName(tag)) = std.fmt.parseInt(u7, argv[i], 0) catch |err| {
                std.log.err("Encountered error '{s}' while trying to parse '{s}' into an unsigned 7-bit integer", .{ @errorName(err), argv[i] });
                return error.InvalidArgumentValue;
            },
            inline .w => |tag| @field(parsed, @tagName(tag)) = std.meta.stringToEnum(Args.Word, argv[i]) orelse
                return error.InvalidArgumentValue,
        }
    }

    if (!arg_set.supersetOf(comptime FieldSet.initMany(&.{ .code, .data }))) {
        return error.MissingArguments;
    }

    return parsed;
}

fn encodeCommand(
    allocator: std.mem.Allocator,
    comptime W: type,
    shard_count: u7,
    shard_size: u7,
    data_filename: []const u8,
    code_prefix: []const u8,
) !void {
    const ec = try erasure.Coder(W).init(allocator, shard_count, shard_size);
    defer ec.deinit(allocator);

    const data_file = try std.fs.cwd().openFile(data_filename, .{});
    defer data_file.close();

    var code_dir = try std.fs.cwd().makeOpenPath(code_prefix, .{});
    defer code_dir.close();

    var code_files: std.BoundedArray(std.fs.File, std.math.maxInt(u8)) = .{};
    defer for (code_files.constSlice()) |cf| cf.close();

    for (0..ec.shardCount()) |i| {
        var code_filename: std.BoundedArray(u8, "255.code".len + 1) = .{};
        code_filename.writer().print("{d}.shard", .{@as(u8, @intCast(i))}) catch |err| switch (err) {
            error.Overflow => unreachable,
        };

        const code_file = code_dir.createFile(code_filename.constSlice(), .{}) catch |err| return err: {
            std.log.err("{s} while creating '{s}'", .{ @errorName(err), code_filename.constSlice() });
            break :err err;
        };
        code_files.appendAssumeCapacity(code_file);
    }

    var code_writers: std.BoundedArray(std.fs.File.Writer, std.math.maxInt(u8)) = .{};
    for (code_files.constSlice()) |cf| code_writers.appendAssumeCapacity(cf.writer());

    _ = try ec.encode(
        data_file.reader(),
        code_writers.constSlice(),
    );
}
fn decodeCommand(
    allocator: std.mem.Allocator,
    comptime W: type,
    shard_count: u7,
    shard_size: u7,
    data_filename: []const u8,
    code_prefix: []const u8,
) !void {
    const ec = try erasure.Coder(W).init(allocator, shard_count, shard_size);
    defer ec.deinit(allocator);

    // TODO: use better RNG source? maybe from std.crypto?
    var prng = std.rand.DefaultPrng.init(@intCast(std.time.microTimestamp()));
    const random = prng.random();

    const excluded_shards = erasure.sampleIndexSet(random, ec.shardCount(), ec.shardCount() - ec.shardsRequired());
    std.log.info("excluding shards {}", .{excluded_shards});

    const data_file = try std.fs.cwd().createFile(data_filename, .{});
    defer data_file.close();

    var code_dir = try std.fs.cwd().makeOpenPath(code_prefix, .{});
    defer code_dir.close();

    var code_files: std.BoundedArray(std.fs.File, std.math.maxInt(u8)) = .{};
    defer for (code_files.constSlice()) |cf| cf.close();

    for (0..ec.shardCount()) |i| {
        if (excluded_shards.isSet(@intCast(i))) continue;
        var code_filename: std.BoundedArray(u8, "255.code".len + 1) = .{};
        code_filename.writer().print("{d}.shard", .{@as(u8, @intCast(i))}) catch |err| switch (err) {
            error.Overflow => unreachable,
        };
        std.log.info("opening {s}", .{code_filename.constSlice()});

        const code_file = code_dir.openFile(code_filename.constSlice(), .{}) catch |err| return err: {
            std.log.err("{s} while opening '{s}'", .{ @errorName(err), code_filename.constSlice() });
            break :err err;
        };
        code_files.appendAssumeCapacity(code_file);
    }

    var code_readers: std.BoundedArray(std.fs.File.Reader, std.math.maxInt(u8)) = .{};
    for (code_files.constSlice()) |cf| code_readers.appendAssumeCapacity(cf.reader());

    _ = try ec.decode(
        excluded_shards,
        data_file.writer(),
        code_readers.constSlice(),
    );
}
