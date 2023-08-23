const std = @import("std");

pub const Matrix = @import("Matrix.zig");
pub const BinaryFiniteField = @import("BinaryFiniteField.zig");
pub const BinaryFieldMatrix = @import("BinaryFieldMatrix.zig");
pub const ErasureCoder = @import("erasure.zig").ErasureCoder;
pub const sample = @import("erasure.zig").sample;

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
    return mainArgs(allocator, cmds);
}

const Args = struct {
    verb: Verb,
    code: []const u8,
    data: []const u8,
    n: u8,
    k: u8,
    w: Word,

    // -n                  code chunks in a block
    // -k                  data chunks in a block
    // -w                  bytes in a word in a chunks
    const Verb = enum { encode, decode };
    const Word = enum { u8, u16, u32, u64 };
};

fn parseArgs(argv: []const []const u8) !Args {
    errdefer std.log.info("Usage: {s}", .{usage});
    var parsed: Args = .{
        .verb = undefined,
        .code = undefined,
        .data = undefined,
        .n = 5,
        .k = 3,
        .w = .u64,
    };

    parsed.verb = std.meta.stringToEnum(Args.Verb, @as(?[]const u8, argv[0]) orelse
        return error.MissingVerb) orelse {
        return error.UnrecognizedVerb;
    };
    const FieldTag = std.meta.FieldEnum(Args);
    var arg_set = std.EnumSet(FieldTag).initMany(&.{ .verb, .n, .k, .w });

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
            inline .n, .k => |tag| @field(parsed, @tagName(tag)) = std.fmt.parseInt(u8, argv[i], 0) catch |err| {
                std.log.err("Encountered error '{s}' while trying to parse '{s}' into an unsigned 8-bit integer", .{ @errorName(err), argv[i] });
                return error.InvalidArgumentValue;
            },
            inline .w => |tag| @field(parsed, @tagName(tag)) = std.meta.stringToEnum(Args.Word, argv[i]) orelse
                return error.InvalidArgumentValue,
        }
    }

    if (!arg_set.supersetOf(comptime std.EnumSet(FieldTag).initMany(&.{ .code, .data }))) {
        return error.MissingArguments;
    }

    return parsed;
}

fn mainArgs(allocator: std.mem.Allocator, cmds: Args) !void {
    const n: u8 = cmds.n;
    const k: u8 = cmds.k;
    switch (cmds.w) {
        inline else => |word| {
            const T = switch (word) {
                .u8 => u8,
                .u16 => u16,
                .u32 => u32,
                .u64 => u64,
            };
            const ec = try ErasureCoder(T).init(allocator, n, k);
            defer ec.deinit(allocator);

            const code_prefix: []const u8 = cmds.code;
            const data_filename: []const u8 = cmds.data;

            switch (cmds.verb) {
                .encode => {
                    const data_file = try std.fs.cwd().openFile(data_filename, .{});
                    defer data_file.close();

                    var code_dir = try std.fs.cwd().makeOpenPath(code_prefix, .{});
                    defer code_dir.close();

                    // var code_files: [n]std.fs.File = undefined;
                    var code_files: std.BoundedArray(std.fs.File, std.math.maxInt(u8)) = .{};
                    defer for (code_files.constSlice()) |cf| cf.close();

                    for (0..n) |i| {
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
                        allocator,
                        data_file.reader(),
                        code_writers.constSlice(),
                    );
                },
                .decode => {
                    // TODO: use better RNG source? maybe from std.crypto?
                    var prng = std.rand.DefaultPrng.init(@intCast(std.time.microTimestamp()));
                    const random = prng.random();

                    const excluded_shards = sample(random, n, n - k);
                    std.log.info("excluding {any}", .{excluded_shards.constSlice()});

                    const data_file = try std.fs.cwd().createFile(data_filename, .{});
                    defer data_file.close();

                    var code_dir = try std.fs.cwd().makeOpenPath(code_prefix, .{});
                    defer code_dir.close();

                    var code_files: std.BoundedArray(std.fs.File, std.math.maxInt(u8)) = .{};
                    defer for (code_files.constSlice()) |cf| cf.close();

                    for (0..n) |i| {
                        if (std.mem.indexOfScalar(u8, excluded_shards.constSlice(), @intCast(i)) != null) continue;
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
                        allocator,
                        excluded_shards.constSlice(),
                        code_readers.constSlice(),
                        data_file.writer(),
                    );
                },
            }
        },
    }
}

pub fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.log.err(format, args);
    std.process.exit(1);
}

test {
    _ = Matrix;
    _ = BinaryFiniteField;
    _ = BinaryFieldMatrix;
    _ = @import("erasure.zig");
}
