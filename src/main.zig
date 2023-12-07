const std = @import("std");

pub const DataOrder = @import("matrix.zig").DataOrder;
pub const Matrix = @import("matrix.zig").Matrix;
pub const BinaryFiniteField = @import("finite_field.zig").BinaryFiniteField;
pub const BinaryFieldMatrix = @import("field_matrix.zig").BinaryFieldMatrix;
pub const ErasureCoder = @import("erasure.zig").ErasureCoder;
pub const sample = @import("erasure.zig").sample;
pub const notIn = @import("erasure.zig").notIn;

const usage =
    \\Usage: eraser [command] [options]
    \\
    \\Commands:
    \\
    \\  encode              encode data
    \\  decode              decode data
    \\
    \\General Options:
    // \\  -N, --code          # code chunks in a block
    // \\  -K, --data          # data chunks in a block
    // \\  -w, --word          # bytes in a word in a chunks
    \\
    \\  -d, --data          name of data fifo file
    \\  -c, --code          prefix of code files
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .thread_safe = true,
    }){};

    {
        const allocator = gpa.allocator();
        const args = try std.process.argsAlloc(allocator);
        defer std.process.argsFree(allocator, args);
        return mainArgs(allocator, args[1..]);
    }

    // we'll arrive here after zap.stop()
    const leaked = gpa.detectLeaks();
    std.debug.print("Leaks detected: {}\n", .{leaked});
}

const Arg = struct {
    cmd: []const u8,
    code: []const u8,
    data: []const u8,
};

fn parseArgs(args: []const []const u8) Arg {
    var parsed: Arg = undefined;

    var bloom: u8 = 0b0;
    for (args) |arg| {
        if (bloom & 0b10 != 0) {
            parsed.code = arg;
            bloom &= 0b11001;
            bloom |= 0b00100;
            continue;
        } else if (bloom & 0b1000 != 0) {
            parsed.data = arg;
            bloom &= 0b00111;
            bloom |= 0b10000;
            continue;
        }
        if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--data")) {
            bloom |= 0b01000;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--code")) {
            bloom |= 0b00010;
        } else if (std.mem.eql(u8, arg, "encode") or std.mem.eql(u8, arg, "decode")) {
            parsed.cmd = arg;
            bloom |= 0b00001;
        } else {
            std.log.info("{s}", .{usage});
            fatal("wrong argument: {s}", .{arg});
        }
    }
    if (bloom != 0b10101) {
        std.log.info("{s}", .{usage});
        fatal("missing argument", .{});
    }
    return parsed;
}

fn mainArgs(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 5) {
        std.log.info("{s}", .{usage});
        fatal("missing arguments", .{});
    }
    // comptime var n = try std.fmt.parseInt(u8, args[1], 10);
    // comptime var k = try std.fmt.parseInt(u8, args[2], 10);
    // comptime var w = try std.fmt.parseInt(u8, args[3], 10);
    const n: u8 = 5;
    const k: u8 = 3;
    const w: type = u64;
    var ec = try ErasureCoder(n, k, w).init(allocator);
    defer ec.deinit();

    const cmds = parseArgs(args);
    const code_prefix: []const u8 = cmds.code;
    const data_filename: []const u8 = cmds.data;

    if (std.mem.eql(u8, cmds.cmd, "encode")) {
        var data_file = try std.fs.cwd().openFile(data_filename, .{});
        defer data_file.close();
        var code_files: [n]std.fs.File = undefined;
        var code_writers: [n]std.fs.File.Writer = undefined;
        for (0..code_files.len) |i| {
            const code_filename = try std.fmt.allocPrint(allocator, "{s}_{d}", .{ code_prefix, i });
            defer allocator.free(code_filename);
            code_files[i] = try std.fs.cwd().createFile(code_filename, .{});
            code_writers[i] = code_files[i].writer();
        }
        _ = try ec.encode(data_file.reader(), &code_writers);
        defer for (code_files) |f| {
            f.close();
        };
    } else if (std.mem.eql(u8, cmds.cmd, "decode")) {
        var prng = std.rand.DefaultPrng.init(@intCast(std.time.microTimestamp()));
        const random = prng.random();
        var excluded_shards = sample(random, n, n - k);
        std.debug.print("excluding {any}\n", .{excluded_shards});

        var data_file = try std.fs.cwd().createFile(data_filename, .{});
        defer data_file.close();

        var code_files: [k]std.fs.File = undefined;
        var code_readers: [k]std.fs.File.Reader = undefined;
        var j: usize = 0;
        for (0..n) |i| {
            if (notIn(&excluded_shards, @intCast(i))) {
                const code_filename = try std.fmt.allocPrint(allocator, "{s}_{d}", .{ code_prefix, i });
                std.debug.print("opening {s}\n", .{code_filename});
                defer allocator.free(code_filename);
                code_files[j] = try std.fs.cwd().openFile(code_filename, .{});
                code_readers[j] = code_files[j].reader();
                j += 1;
            }
        }
        _ = try ec.decode(&excluded_shards, &code_readers, data_file.writer());
        defer for (code_files) |f| {
            f.close();
        };
    } else {
        std.log.info("{s}", .{usage});
        fatal("invalid command: {s}\n", .{args[1]});
    }
}

pub fn fatal(comptime format: []const u8, args: anytype) noreturn {
    std.log.err(format, args);
    std.process.exit(1);
}

test {
    _ = @import("matrix.zig");
    _ = @import("finite_field.zig");
    _ = @import("field_matrix.zig");
    _ = @import("erasure.zig");
}
