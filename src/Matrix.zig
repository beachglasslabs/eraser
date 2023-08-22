///! Row-major Matrix 8 bit indexed columns and rows
const std = @import("std");
const assert = std.debug.assert;
const mulWide = std.math.mulWide;

const util = @import("util.zig");

const Matrix = @This();
data: [*]align(16) u8,
num_rows: u8,
num_cols: u8,

/// Caller allows Matrix to manage the memory, should call `deinit`.
pub fn init(allocator: std.mem.Allocator, rows: u8, cols: u8) std.mem.Allocator.Error!Matrix {
    const data = try allocator.alignedAlloc(u8, 16, mulWide(u8, rows, cols));
    errdefer allocator.free(data);
    return Matrix.initWith(data, rows, cols);
}

/// Caller manages the memory, should not call `deinit`,
/// unless the caller guarantees that `deinit` is called
/// with the same `std.mem.Allocator` that was used to
/// allocate `data`, and that `data` is not a sub-slice
/// of any allocation.
pub inline fn initWith(data: []align(16) u8, rows: u8, cols: u8) Matrix {
    assert(mulWide(u8, rows, cols) == data.len);
    @memset(data, 0);
    return .{
        .data = data.ptr,
        .num_rows = rows,
        .num_cols = cols,
    };
}

/// See the doc comments on `init` and `initWith` for when it is
/// allowed to call this function.
pub inline fn deinit(self: Matrix, allocator: std.mem.Allocator) void {
    allocator.free(self.getDataSlice());
}

/// Moves the matrix by copying the pointers and data,
/// emptying the original (such that freeing it would be the,
/// same as freeing and empty slice), and returns the copy.
pub inline fn move(matrix: *Matrix) Matrix {
    const moved = matrix.*;
    matrix.* = Matrix{
        .data = undefined,
        .num_rows = 0,
        .num_cols = 0,
    };
    return moved;
}

pub fn getCellCount(self: Matrix) u16 {
    return mulWide(u8, self.num_rows, self.num_cols);
}

pub const CellIndex = packed struct(u16) { row: u8, col: u8 };

pub fn getPtr(self: Matrix, idx: CellIndex) *u8 {
    assert(idx.row < self.num_rows and idx.col < self.num_cols);
    const i = idx.row * self.num_cols + idx.col;
    return &self.data[i];
}
pub fn get(self: Matrix, idx: CellIndex) u8 {
    return self.getPtr(idx).*;
}
pub fn set(self: *Matrix, idx: CellIndex, value: u8) void {
    self.getPtr(idx).* = value;
}

pub fn transpose(self: *Matrix) void {
    assert(self.num_rows == self.num_cols);
    for (0..self.num_rows) |row| {
        for (0..self.num_cols) |col| {
            if (row == col) break;
            const row_col_idx: CellIndex = .{ .row = @intCast(row), .col = @intCast(col) };
            const col_row_idx: CellIndex = .{ .row = @intCast(col), .col = @intCast(row) };

            const at_row_col = self.get(row_col_idx);
            const at_col_row = self.get(col_row_idx);

            self.set(row_col_idx, at_col_row);
            self.set(col_row_idx, at_row_col);
        }
    }
}

pub fn getSlice(self: *const Matrix, col: u8) []u8 {
    assert(col < self.num_rows);
    const i = mulWide(u8, col, self.num_cols);
    return self.data[i..][0..self.num_cols];
}

pub const getRow = getSlice;

pub inline fn colIterator(self: *const Matrix, col: u8) ColIterator {
    return .{
        .mat = self,
        .row_index = 0,
        .col_index = col,
    };
}

pub const ColIterator = struct {
    mat: *const Matrix,
    row_index: u8,
    col_index: u8,
    const Self = @This();

    pub inline fn next(self: *Self) ?u8 {
        const ptr = self.nextPtr() orelse return null;
        return ptr.*;
    }
    pub inline fn nextPtr(self: *Self) ?*u8 {
        if (self.row_index == self.mat.num_rows) return null;
        self.row_index += 1;
        return self.mat.getPtr(.{
            .row = self.row_index - 1,
            .col = self.col_index,
        });
    }
};

pub fn setSlice(self: *Matrix, rc: u8, new_rc: []const u8) void {
    assert(rc < self.num_rows);
    assert(new_rc.len == self.num_cols);
    util.safeMemcpy(self.getSlice(rc)[0..self.num_cols], new_rc);
}

pub fn setRow(self: *Matrix, row: u8, new_row: []const u8) void {
    self.setSlice(row, new_row);
}

pub fn setCol(self: *Matrix, col: u8, new_col: []const u8) void {
    assert(col < self.num_cols and new_col.len >= self.num_rows);
    for (0..self.num_rows) |i| {
        self.set(.{ .row = @intCast(i), .col = col }, new_col[i]);
    }
}

pub fn format(self: *const Matrix, comptime _: []const u8, _: std.fmt.FormatOptions, stream: anytype) !void {
    try stream.print("\n{d}x{d} row ->\n", .{ self.num_rows, self.num_cols });
    for (0..self.num_rows) |r| {
        for (0..self.num_cols) |c| {
            try stream.print("{d} ", .{self.get(.{ .row = @intCast(r), .col = @intCast(c) })});
        }
        try stream.writeByte('\n');
    }
}

inline fn getDataSlice(self: Matrix) []align(16) u8 {
    return self.data[0..self.getCellCount()];
}

test "basic matrix" {
    var mat = try Matrix.init(std.testing.allocator, 3, 2);
    defer mat.deinit(std.testing.allocator);

    mat.set(.{ .row = 0, .col = 0 }, 1);
    mat.set(.{ .row = 0, .col = 1 }, 2);
    mat.set(.{ .row = 1, .col = 1 }, 4);
    mat.set(.{ .row = 2, .col = 0 }, 5);
    try expectSegment(&mat, .col, 0, &.{ 1, 0, 5 });
    try expectSegment(&mat, .col, 1, &.{ 2, 4, 0 });

    mat.setCol(1, &.{ 7, 8, 9 });
    try expectSegment(&mat, .col, 1, &.{ 7, 8, 9 });

    mat.setRow(1, &.{ 6, 7 });
    try std.testing.expectEqual(mat.get(.{ .row = 1, .col = 0 }), 6);
    try std.testing.expectEqual(mat.get(.{ .row = 1, .col = 1 }), 7);
}

test "square matrix" {
    var mat = try Matrix.init(std.testing.allocator, 3, 3);
    defer mat.deinit(std.testing.allocator);

    mat.set(.{ .row = 0, .col = 0 }, 1);
    mat.set(.{ .row = 1, .col = 0 }, 2);
    mat.set(.{ .row = 2, .col = 0 }, 3);
    mat.set(.{ .row = 0, .col = 1 }, 4);
    mat.set(.{ .row = 1, .col = 1 }, 5);
    mat.set(.{ .row = 2, .col = 1 }, 6);
    mat.set(.{ .row = 0, .col = 2 }, 7);
    mat.set(.{ .row = 1, .col = 2 }, 8);
    mat.set(.{ .row = 2, .col = 2 }, 9);
    try expectSegment(&mat, .col, 0, &.{ 1, 2, 3 });
    try expectSegment(&mat, .col, 1, &.{ 4, 5, 6 });
    try expectSegment(&mat, .col, 2, &.{ 7, 8, 9 });
}

test "matrix transposition" {
    var mat = try Matrix.init(std.testing.allocator, 3, 3);
    defer mat.deinit(std.testing.allocator);

    mat.set(.{ .row = 0, .col = 0 }, 1);
    mat.set(.{ .row = 1, .col = 0 }, 2);
    mat.set(.{ .row = 2, .col = 0 }, 3);
    mat.set(.{ .row = 0, .col = 1 }, 4);
    mat.set(.{ .row = 1, .col = 1 }, 5);
    mat.set(.{ .row = 2, .col = 1 }, 6);
    mat.set(.{ .row = 0, .col = 2 }, 7);
    mat.set(.{ .row = 1, .col = 2 }, 8);
    mat.set(.{ .row = 2, .col = 2 }, 9);
    mat.transpose();
    try expectSegment(&mat, .row, 0, &.{ 1, 2, 3 });
    try expectSegment(&mat, .row, 1, &.{ 4, 5, 6 });
    try expectSegment(&mat, .row, 2, &.{ 7, 8, 9 });
}

test "rows and cols" {
    var mat = try Matrix.init(std.testing.allocator, 4, 3);
    defer mat.deinit(std.testing.allocator);

    mat.setRow(0, &.{ 1, 2, 3 });
    mat.setRow(1, &.{ 5, 6, 7 });
    mat.setRow(2, &.{ 9, 10, 11 });
    mat.setRow(3, &.{ 13, 14, 15 });
    try expectSegment(&mat, .row, 0, &.{ 1, 2, 3 });
    try expectSegment(&mat, .row, 1, &.{ 5, 6, 7 });
    try expectSegment(&mat, .row, 2, &.{ 9, 10, 11 });
    try expectSegment(&mat, .row, 3, &.{ 13, 14, 15 });

    mat.setCol(1, &.{ 4, 8, 12, 16 });
    try expectSegment(&mat, .row, 0, &.{ 1, 4, 3 });
    try expectSegment(&mat, .row, 1, &.{ 5, 8, 7 });
    try expectSegment(&mat, .row, 2, &.{ 9, 12, 11 });
    try expectSegment(&mat, .row, 3, &.{ 13, 16, 15 });

    try expectSegment(&mat, .col, 0, &.{ 1, 5, 9, 13 });
    try expectSegment(&mat, .col, 1, &.{ 4, 8, 12, 16 });
    try expectSegment(&mat, .col, 2, &.{ 3, 7, 11, 15 });

    var m2 = try Matrix.init(std.testing.allocator, 3, 2);
    defer m2.deinit(std.testing.allocator);

    m2.setCol(0, &.{ 1, 3, 7 });
    m2.setCol(1, &.{ 2, 5, 2 });
    try expectSegment(&m2, .col, 0, &.{ 1, 3, 7 });

    m2.setRow(1, &.{ 9, 8 });
    try expectSegment(&m2, .row, 0, &.{ 1, 2 });
    try expectSegment(&m2, .row, 1, &.{ 9, 8 });
    try expectSegment(&m2, .row, 2, &.{ 7, 2 });
}

fn expectSegment(
    matrix: *const Matrix,
    segment_order: enum { row, col },
    rc_idx: u8,
    expected_values: []const u8,
) !void {
    switch (segment_order) {
        .row => try std.testing.expectEqualSlices(u8, expected_values, matrix.getRow(rc_idx)),
        .col => {
            const actual_count = matrix.num_rows;

            const actual_values = try std.testing.allocator.alloc(u8, actual_count);
            defer std.testing.allocator.free(actual_values);
            @memset(actual_values, 0);

            var amt: usize = actual_values.len;

            var iter = matrix.colIterator(rc_idx);
            for (actual_values, 0..) |*actual, i| actual.* = iter.next() orelse {
                amt = i;
                break;
            };
            try std.testing.expectEqual(@as(?u8, null), iter.next());
            try std.testing.expectEqualSlices(u8, expected_values, actual_values[0..amt]);
        },
    }
}
