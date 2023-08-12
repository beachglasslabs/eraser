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
        var allocator = gpa.allocator();
        const args = try std.process.argsAlloc(allocator);
        defer std.process.argsFree(allocator, args);
        return mainArgs(allocator, args[1..]);
    }

    // we'll arrive here after zap.stop()
    const leaked = gpa.detectLeaks();
    std.debug.print("Leaks detected: {}\n", .{leaked});
}

fn mainArgs(allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (args.len < 5) {
        std.log.info("{s}", .{usage});
        fatal("expected command argument", .{});
    }
    // comptime var n = try std.fmt.parseInt(u8, args[1], 10);
    // comptime var k = try std.fmt.parseInt(u8, args[2], 10);
    // comptime var w = try std.fmt.parseInt(u8, args[3], 10);
    comptime var n: u8 = 5;
    comptime var k: u8 = 3;
    comptime var w: type = u64;
    var ec = try ErasureCoder(n, k, w).init(allocator);
    defer ec.deinit();

    const cmd = args[0];
    var code_prefix: []const u8 = undefined;
    var data_filename: []const u8 = undefined;
    if (std.mem.eql(u8, args[1], "-d") or std.mem.eql(u8, args[1], "--data")) {
        data_filename = args[2];
        if (std.mem.eql(u8, args[3], "-c") or std.mem.eql(u8, args[3], "--code")) {
            code_prefix = args[4];
        } else {
            std.log.info("{s}", .{usage});
            fatal("missing code argument: {s}\n", .{args[3]});
        }
    } else if (std.mem.eql(u8, args[1], "-c") or std.mem.eql(u8, args[1], "--code")) {
        code_prefix = args[3];
        if (std.mem.eql(u8, args[3], "-d") or std.mem.eql(u8, args[3], "--data")) {
            data_filename = args[4];
        } else {
            std.log.info("{s}", .{usage});
            fatal("missing data argument: {s}\n", .{args[3]});
        }
    } else {
        std.log.info("{s}", .{usage});
        fatal("missing data/code argument: {s}\n", .{args[1]});
    }

    if (std.mem.eql(u8, cmd, "encode")) {
        var data_file = try std.fs.cwd().openFile(data_filename, .{});
        defer data_file.close();
        var code_files: [n]std.fs.File = undefined;
        var code_writers: [n]std.fs.File.Writer = undefined;
        for (0..code_files.len) |i| {
            var code_filename = try std.fmt.allocPrint(allocator, "{s}_{d}", .{ code_prefix, i });
            defer allocator.free(code_filename);
            code_files[i] = try std.fs.cwd().createFile(code_filename, .{});
            code_writers[i] = code_files[i].writer();
        }
        _ = try ec.encode(data_file.reader(), &code_writers);
        defer for (code_files) |f| {
            f.close();
        };
    } else if (std.mem.eql(u8, cmd, "decode")) {
        var prng = std.rand.DefaultPrng.init(@intCast(std.time.microTimestamp()));
        var random = prng.random();
        var excluded_shards = sample(random, n, n - k);
        std.debug.print("excluding {any}\n", .{excluded_shards});

        var data_file = try std.fs.cwd().createFile(data_filename, .{});
        defer data_file.close();

        var code_files: [k]std.fs.File = undefined;
        var code_readers: [k]std.fs.File.Reader = undefined;
        var j: usize = 0;
        for (0..n) |i| {
            if (notIn(&excluded_shards, @intCast(i))) {
                var code_filename = try std.fmt.allocPrint(allocator, "{s}_{d}", .{ code_prefix, i });
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
