const std = @import("std");

pub fn factorial(comptime n: u8) comptime_int {
    comptime var r = 1;
    inline for (1..(n + 1)) |i| {
        r *= i;
    }
    return r;
}

pub fn numChosen(comptime m: u8, comptime n: u8) comptime_int {
    return factorial(m) / (factorial(n) * factorial(m - n));
}

pub fn ChosenType(comptime m: u8, comptime n: u8) type {
    comptime var t = numChosen(m, n);
    return [t][n]u8;
}

pub fn choose(comptime l: []const u8, comptime k: u8) ChosenType(l.len, k) {
    std.debug.assert(l.len >= k);
    std.debug.assert(k > 0);

    var ret: ChosenType(l.len, k) = std.mem.zeroes(ChosenType(l.len, k));

    if (k == 1) {
        inline for (0..l.len) |i| {
            ret[i] = [k]u8{l[i]};
        }
        return ret;
    }
    comptime var c = choose(l[1..], k - 1);
    comptime var i = 0;
    inline for (0..(l.len - 1)) |m| {
        inline for (0..c.len) |n| {
            if (l[m] < c[n][0]) {
                ret[i][0] = l[m];
                inline for (0..c[n].len) |j| {
                    ret[i][j + 1] = c[n][j];
                }
                i += 1;
            }
        }
    }
    return ret;
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

test "x choose y" {
    // var list = choose(&[_]u8{ 0, 1, 2, 3, 4 }, 2);
    // for (0..list.len) |i| {
    //     std.debug.print("choose[{d}]={any}\n", .{ i, list[i] });
    // }
    var list1 = choose(&[_]u8{9}, 1);
    try std.testing.expectEqual(list1.len, 1);
    try std.testing.expectEqual(list1[0], [1]u8{9});

    var list2 = choose(&[_]u8{ 8, 9 }, 1);
    try std.testing.expectEqual(list2.len, 2);
    try std.testing.expectEqual(list2[0], [1]u8{8});
    try std.testing.expectEqual(list2[1], [1]u8{9});

    var list3 = choose(&[_]u8{ 7, 8, 9 }, 1);
    try std.testing.expectEqual(list3.len, 3);
    try std.testing.expectEqual(list3[0], [1]u8{7});
    try std.testing.expectEqual(list3[1], [1]u8{8});
    try std.testing.expectEqual(list3[2], [1]u8{9});

    var list4 = choose(&[_]u8{ 8, 9 }, 2);
    try std.testing.expectEqual(list4.len, 1);
    try std.testing.expectEqual(list4[0], [2]u8{ 8, 9 });

    var list5 = choose(&[_]u8{ 7, 8, 9 }, 2);
    try std.testing.expectEqual(list5.len, 3);
    try std.testing.expectEqual(list5[0], [2]u8{ 7, 8 });
    try std.testing.expectEqual(list5[1], [2]u8{ 7, 9 });
    try std.testing.expectEqual(list5[2], [2]u8{ 8, 9 });

    var list6 = choose(&[_]u8{ 6, 7, 8, 9 }, 2);
    try std.testing.expectEqual(list6.len, 6);
    try std.testing.expectEqual(list6[0], [2]u8{ 6, 7 });
    try std.testing.expectEqual(list6[1], [2]u8{ 6, 8 });
    try std.testing.expectEqual(list6[2], [2]u8{ 6, 9 });
    try std.testing.expectEqual(list6[3], [2]u8{ 7, 8 });
    try std.testing.expectEqual(list6[4], [2]u8{ 7, 9 });
    try std.testing.expectEqual(list6[5], [2]u8{ 8, 9 });

    var list7 = choose(&[_]u8{ 7, 8, 9 }, 3);
    try std.testing.expectEqual(list7.len, 1);
    try std.testing.expectEqual(list7[0], [3]u8{ 7, 8, 9 });

    var list8 = choose(&[_]u8{ 6, 7, 8, 9 }, 3);
    try std.testing.expectEqual(list8.len, 4);
    try std.testing.expectEqual(list8[0], [3]u8{ 6, 7, 8 });
    try std.testing.expectEqual(list8[1], [3]u8{ 6, 7, 9 });
    try std.testing.expectEqual(list8[2], [3]u8{ 6, 8, 9 });
    try std.testing.expectEqual(list8[3], [3]u8{ 7, 8, 9 });
}
