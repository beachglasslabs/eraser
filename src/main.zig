const std = @import("std");
const testing = std.testing;
const Field = @import("field.zig");

fn initTest(allocator: std.mem.Allocator) !std.ArrayList(Field) {
    var fields = try std.ArrayList(Field).initCapacity(allocator, 7);

    for (1..8) |n| {
        try fields.append(try Field.init(n));
    }

    return fields;
}

test "basic add functionality" {
    const fields = try initTest(testing.allocator);
    defer fields.deinit();
    for (fields.items) |field| {
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
    const fields = try initTest(testing.allocator);
    defer fields.deinit();
    for (fields.items) |field| {
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
    const fields = try initTest(testing.allocator);
    defer fields.deinit();
    for (fields.items) |field| {
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
    const fields = try initTest(testing.allocator);
    defer fields.deinit();
    for (fields.items) |field| {
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
    const f2 = try Field.init(2);
    const f3 = try Field.init(3);
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
}
