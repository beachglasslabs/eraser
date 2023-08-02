const std = @import("std");

pub fn factorial(comptime n: u8) comptime_int {
    comptime var r = 1;
    inline for (1..(n + 1)) |i| {
        r *= i;
    }
    return r;
}

pub fn numChosen(comptime m: comptime_int, comptime n: comptime_int) comptime_int {
    return factorial(m) / (factorial(n) * factorial(m - n));
}

pub fn ChosenType(comptime m: comptime_int, comptime n: comptime_int) type {
    comptime var t = numChosen(m, n);
    return [t][n]u8;
}

pub fn choose(comptime l: []const u8, comptime k: comptime_int) ChosenType(l.len, k) {
    var results: ChosenType(l.len, k) = std.mem.zeroes(ChosenType(l.len, k));
    comptime var c = 0;
    inline for (0..l.len - 1) |a| {
        inline for (1..l.len) |b| {
            if (a < b) {
                // std.debug.print("adding [{d}, {d}]\n", .{ a, b });
                results[c] = [k]u8{ @intCast(a), @intCast(b) };
                c += 1;
            }
        }
    }
    // std.debug.print("added {d} pairs\n", .{c});
    return results;
}

test "factorial" {
    try std.testing.expectEqual(factorial(5), 120);
    try std.testing.expectEqual(factorial(3), 6);
    try std.testing.expectEqual(factorial(2), 2);
    try std.testing.expectEqual(factorial(1), 1);
    try std.testing.expectEqual(factorial(0), 1);
}

test "number of (x choose y)" {
    try std.testing.expectEqual(numChosen(5, 2), 10);
    try std.testing.expectEqual(numChosen(5, 3), 10);
    try std.testing.expectEqual(numChosen(12, 3), 220);
}

test "chosen return type" {
    try std.testing.expectEqual(@TypeOf(ChosenType(5, 2)), @TypeOf([10][2]u8));
    try std.testing.expectEqual(ChosenType(5, 2), [10][2]u8);
    try std.testing.expectEqual(ChosenType(5, 3), [10][3]u8);
}

test "x choose y" {}
