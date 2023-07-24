const std = @import("std");
const testing = std.testing;
const bff = @import("field.zig");

test "basic add functionality" {
    inline for (comptime 1..8) |i| {
        const field = try bff.BinaryFiniteField(i).init();
        var negatives = std.AutoHashMap(usize, usize).init(testing.allocator);
        defer negatives.deinit();
        for (0..field.order) |a| {
            for (0..field.order) |b| {
                var result = try field.add(a, b);
                try testing.expect(result < field.order);
                try testing.expectEqual(result, try field.add(b, a));
                if (result == 0) {
                    try negatives.put(a, b);
                    try negatives.put(b, a);
                }
            }
        }
        try testing.expectEqual(@as(u32, field.order), negatives.count());
    }
}

test "basic subtract functionality" {
    inline for (comptime 1..8) |i| {
        const field = try bff.BinaryFiniteField(i).init();
        for (0..field.order) |a| {
            for (0..field.order) |b| {
                var result = try field.sub(a, b);
                try testing.expect(result < field.order);
                if (a == b) {
                    try testing.expectEqual(result, 0);
                } else {
                    try testing.expect(result > 0);
                }
            }
        }
    }
}

test "basic multiply functionality" {
    inline for (comptime 1..8) |i| {
        const field = try bff.BinaryFiniteField(i).init();
        var reciprocals = std.AutoHashMap(usize, usize).init(testing.allocator);
        defer reciprocals.deinit();
        for (0..field.order) |a| {
            for (0..field.order) |b| {
                var result = try field.mul(a, b);
                try testing.expectEqual(result, try field.mul(b, a));
                if (result == 0) {
                    try testing.expect(a == 0 or b == 0);
                }
                if (result == 1) {
                    try testing.expect(a != 0 and b != 0);
                    try reciprocals.put(a, b);
                    try reciprocals.put(b, a);
                }
            }
        }
        try testing.expectEqual(@as(u32, field.order - 1), reciprocals.count());
    }
}

test "basic divide functionality" {
    inline for (comptime 1..8) |i| {
        const field = try bff.BinaryFiniteField(i).init();
        for (0..field.order) |a| {
            for (0..field.order) |b| {
                if (b == 0) continue;
                var result = try field.div(a, b);
                try testing.expect(result < field.order);
                if (a == b) {
                    try testing.expectEqual(result, 1);
                } else {
                    try testing.expect(result != 1);
                }
            }
        }
    }
}

test "convert to matrix" {
    const f2 = try bff.BinaryFiniteField(2).init();
    const f3 = try bff.BinaryFiniteField(3).init();
    const m2 = try f2.toMatrix(testing.allocator, 2);
    defer {
        for (0..m2.len) |r| {
            defer testing.allocator.free(m2[r]);
        }
        testing.allocator.free(m2);
    }
    // std.debug.print("\nmatrix(2x2) of 01\n", .{});
    // for (0..f2.exp) |r| {
    //     for (0..f2.exp) |c| {
    //         std.debug.print("{b} ", .{m2[r][c]});
    //     }
    //     std.debug.print("\n", .{});
    // }
    try testing.expectEqualSlices(u8, m2[0], &[_]u8{ 0, 1 });
    try testing.expectEqualSlices(u8, m2[1], &[_]u8{ 1, 1 });
    const m3 = try f3.toMatrix(testing.allocator, 2);
    defer {
        for (0..m3.len) |r| {
            defer testing.allocator.free(m3[r]);
        }
        testing.allocator.free(m3);
    }
    // std.debug.print("\nmatrix(3x3) of 010\n", .{});
    // for (0..f3.exp) |r| {
    //     for (0..f3.exp) |c| {
    //         std.debug.print("{b} ", .{m3[r][c]});
    //     }
    //     std.debug.print("\n", .{});
    // }
    try testing.expectEqualSlices(u8, m3[0], &[_]u8{ 0, 0, 1 });
    try testing.expectEqualSlices(u8, m3[1], &[_]u8{ 1, 0, 1 });
    try testing.expectEqualSlices(u8, m3[2], &[_]u8{ 0, 1, 0 });
    const m5 = try f3.toMatrix(testing.allocator, 5);
    defer {
        for (0..m5.len) |r| {
            defer testing.allocator.free(m5[r]);
        }
        testing.allocator.free(m5);
    }
    try testing.expectEqualSlices(u8, m5[0], &[_]u8{ 1, 1, 0 });
    try testing.expectEqualSlices(u8, m5[1], &[_]u8{ 0, 0, 1 });
    try testing.expectEqualSlices(u8, m5[2], &[_]u8{ 1, 0, 0 });
    const m6 = try f3.toMatrix(testing.allocator, 6);
    defer {
        for (0..m6.len) |r| {
            defer testing.allocator.free(m6[r]);
        }
        testing.allocator.free(m6);
    }
    try testing.expectEqualSlices(u8, m6[0], &[_]u8{ 0, 1, 1 });
    try testing.expectEqualSlices(u8, m6[1], &[_]u8{ 1, 1, 0 });
    try testing.expectEqualSlices(u8, m6[2], &[_]u8{ 1, 1, 1 });
    const c6 = try f3.simdColMat(testing.allocator, 6);
    defer testing.allocator.free(c6);
    // for (0..c6.len) |c| {
    //     std.debug.print("simd.col[{d}]: {}\n", .{ c, c6[c] });
    // }
    try testing.expectEqual(c6[0], @Vector(3, u8){ 0, 1, 1 });
    try testing.expectEqual(c6[1], @Vector(3, u8){ 1, 1, 1 });
    try testing.expectEqual(c6[2], @Vector(3, u8){ 1, 0, 1 });
    const r6 = try f3.simdMatrix(testing.allocator, 6);
    defer testing.allocator.free(r6);
    // for (0..r6.len) |r| {
    //     std.debug.print("simd.row[{d}]: {}\n", .{ r, r6[r] });
    // }
    try testing.expectEqual(r6[0], @Vector(3, u8){ 0, 1, 1 });
    try testing.expectEqual(r6[1], @Vector(3, u8){ 1, 1, 0 });
    try testing.expectEqual(r6[2], @Vector(3, u8){ 1, 1, 1 });
}
