const std = @import("std");
const testing = std.testing;
const bff = @import("field.zig");
const Matrix = @import("matrix.zig");

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

test "matrix" {
    var m = try Matrix.init(testing.allocator, Matrix.DataOrder.row, 3, 2);
    defer m.deinit();
    m.set(0, 0, 1);
    m.set(0, 1, 2);
    m.set(1, 1, 4);
    m.set(2, 0, 5);
    m.print();
    for (0..m.num_cols) |c| {
        const col = try m.getCol(c);
        defer testing.allocator.free(col);
        std.debug.print("col[{d}]={any}\n", .{ c + 1, col });
    }

    var m2 = try Matrix.init(testing.allocator, Matrix.DataOrder.col, 3, 3);
    defer m2.deinit();
    m2.set(0, 0, 1);
    m2.set(1, 0, 2);
    m2.set(2, 0, 3);
    m2.set(0, 1, 4);
    m2.set(1, 1, 5);
    m2.set(2, 1, 6);
    m2.set(0, 2, 7);
    m2.set(1, 2, 8);
    m2.set(2, 2, 9);
    m2.print();

    for (0..m2.num_rows) |r| {
        const row = try m2.getRow(r);
        defer testing.allocator.free(row);
        std.debug.print("row[{d}]={any}\n", .{ r + 1, row });
    }
    for (0..m2.num_cols) |c| {
        const col = try m2.getCol(c);
        defer testing.allocator.free(col);
        std.debug.print("col[{d}]={any}\n", .{ c + 1, col });
    }
}
