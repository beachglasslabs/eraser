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
