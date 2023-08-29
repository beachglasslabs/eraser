///! Row-major Matrix 8 bit indexed columns and rows
const std = @import("std");
const assert = std.debug.assert;
const mulWide = std.math.mulWide;

const util = @import("util.zig");

const Matrix = @This();
data: [*]align(16) u8 = undefined,
num_rows: u8 = 0,
num_cols: u8 = 0,

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
pub fn initWith(data: []align(16) u8, rows: u8, cols: u8) Matrix {
    assert(mulWide(u8, rows, cols) == data.len);
    @memset(data, 0);
    return .{
        .data = data.ptr,
        .num_rows = rows,
        .num_cols = cols,
    };
}

pub fn clone(self: Matrix, allocator: std.mem.Allocator) !Matrix {
    const data = try allocator.alignedAlloc(u8, 16, self.getCellCount());
    errdefer allocator.free(data);
    return self.cloneWith(data);
}

pub fn cloneWith(self: Matrix, data: []align(16) u8) Matrix {
    @memcpy(data, self.getDataSlice());
    return Matrix.initWith(data, self.num_rows, self.num_cols);
}

/// Attempts to reallocate the matrix to the specified row & column lengths, zeroing out the cells.
/// Returns true if the resize was successful. Otherwise, returns false, and the data is left unmodified.
pub fn resizeAndReset(self: *Matrix, allocator: std.mem.Allocator, rows: u8, cols: u8) bool {
    const new_size = mulWide(u8, rows, cols);

    const result = allocator.resize(self.getDataSlice(), new_size);
    if (result) {
        const resized_slice = self.data[0..new_size];
        self.* = Matrix.initWith(resized_slice, rows, cols);
    }
    return result;
}

/// See the doc comments on `init` and `initWith` for when it is
/// allowed to call this function.
pub inline fn deinit(self: Matrix, allocator: std.mem.Allocator) void {
    allocator.free(self.getDataSlice());
}

pub inline fn getCellCount(self: Matrix) u16 {
    return mulWide(u8, self.num_rows, self.num_cols);
}

pub inline fn numRows(self: Matrix) u8 {
    return self.num_rows;
}
pub inline fn numCols(self: Matrix) u8 {
    return self.num_cols;
}

pub const CellIndex = packed struct(u16) { row: u8, col: u8 };

pub fn getPtr(self: Matrix, idx: CellIndex) *u8 {
    if (idx.row >= self.numRows()) std.debug.print("{} {}\n", .{ idx.row, self.numRows() });
    assert(idx.row < self.numRows());
    assert(idx.col < self.numCols());
    const i = mulWide(u8, idx.row, self.num_cols) + idx.col;
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

pub fn loadRow(self: Matrix, row: u8, dst: []u8) []u8 {
    @memcpy(dst[0..self.numRows()], self.getRow(row));
}

pub fn getSlice(self: Matrix, row: u8) []u8 {
    assert(row < self.num_rows);
    const i = mulWide(u8, row, self.num_cols);
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

    pub inline fn next(self: *ColIterator) ?u8 {
        const ptr = self.nextPtr() orelse return null;
        return ptr.*;
    }
    pub inline fn nextPtr(self: *ColIterator) ?*u8 {
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

pub inline fn setRow(self: *Matrix, row: u8, new_row: []const u8) void {
    self.setSlice(row, new_row);
}

pub fn setCol(self: *Matrix, col: u8, new_col: []const u8) void {
    assert(col < self.num_cols and new_col.len >= self.num_rows);
    for (0..self.num_rows) |i| {
        self.set(.{ .row = @intCast(i), .col = col }, new_col[i]);
    }
}

/// All integers in the provided each of the slices should be unique
pub inline fn subView(
    self: *const Matrix,
    excluded_rows: []const u8,
    excluded_cols: []const u8,
) SubView {
    const full_view = SubView{
        .parent = self,
        .excluded_rows = SubView.SegmentSet.initEmpty(),
        .excluded_cols = SubView.SegmentSet.initEmpty(),
    };
    return full_view.subView(excluded_rows, excluded_cols);
}

pub const SubView = struct {
    parent: *const Matrix,
    // excluded_rows: []const u8,
    // excluded_cols: []const u8,
    excluded_rows: SegmentSet = SegmentSet.initEmpty(),
    excluded_cols: SegmentSet = SegmentSet.initEmpty(),

    pub const SegmentSet = std.bit_set.ArrayBitSet(u32, std.math.maxInt(u8));

    pub fn subView(
        self: SubView,
        excluded_rows: []const u8,
        excluded_cols: []const u8,
    ) SubView {
        assert(excluded_rows.len <= self.numRows());
        assert(excluded_cols.len <= self.numCols());

        var ex_rows = self.excluded_rows;
        for (excluded_rows) |row| {
            assert(row < self.numRows());
            ex_rows.set(subRcIndexToParentRcIdx(row, self.excluded_rows));
        }

        var ex_cols = self.excluded_cols;
        for (excluded_cols) |col| {
            assert(col < self.numCols());
            ex_cols.set(subRcIndexToParentRcIdx(col, self.excluded_cols));
        }

        return .{
            .parent = self.parent,
            .excluded_rows = ex_rows,
            .excluded_cols = ex_cols,
        };
    }

    pub fn copyInto(self: SubView, dst: Matrix) void {
        assert(self.numRows() == dst.numRows());
        assert(self.numCols() == dst.numCols());

        for (0..dst.numRows()) |row_idx| {
            for (dst.getRow(@intCast(row_idx)), 0..) |*cell, col_idx| {
                cell.* = self.get(.{
                    .row = @intCast(row_idx),
                    .col = @intCast(col_idx),
                });
            }
        }
    }

    pub fn getCellCount(self: SubView) u16 {
        return mulWide(u8, self.numRows(), self.numCols());
    }
    pub fn numRows(self: SubView) u8 {
        const ex: u8 = @intCast(self.excluded_rows.count());
        return self.parent.numRows() - ex;
    }
    pub fn numCols(self: SubView) u8 {
        const ex: u8 = @intCast(self.excluded_cols.count());
        return self.parent.numCols() - ex;
    }

    pub fn getPtr(self: SubView, idx: CellIndex) *u8 {
        return self.parent.getPtr(self.subIndexToParentIdx(idx));
    }
    pub inline fn get(self: SubView, idx: CellIndex) u8 {
        return self.getPtr(idx).*;
    }
    pub inline fn set(self: SubView, idx: CellIndex, val: u8) void {
        self.getPtr(idx).* = val;
    }

    inline fn subIndexToParentIdx(self: SubView, idx: CellIndex) CellIndex {
        assert(idx.row < self.numRows());
        assert(idx.col < self.numCols());
        return CellIndex{
            .row = subRcIndexToParentRcIdx(idx.row, self.excluded_rows),
            .col = subRcIndexToParentRcIdx(idx.col, self.excluded_cols),
        };
    }

    fn subRcIndexToParentRcIdx(rc_idx: u8, excluded: SegmentSet) u8 {
        var result: u8 = rc_idx;
        var iter = excluded.iterator(.{});
        while (true) {
            const ex: u8 = @intCast(iter.next() orelse break);
            if (result < ex) break;
            result += 1;
        }
        return result;
    }

    pub inline fn rowIterator(self: *const SubView, row_idx: u8) SubIterator(.row) {
        return .{
            .view = self,
            .row_index = row_idx,
            .col_index = 0,
        };
    }

    pub inline fn colIterator(self: *const SubView, col_idx: u8) SubIterator(.col) {
        return .{
            .view = self,
            .row_index = 0,
            .col_index = col_idx,
        };
    }

    pub const SubIteratorOrder = enum { row, col };
    pub fn SubIterator(comptime order: SubIteratorOrder) type {
        return struct {
            view: *const SubView,
            row_index: u8,
            col_index: u8,
            const Self = @This();

            pub inline fn next(self: *Self) ?u8 {
                const ptr = self.nextPtr() orelse return null;
                return ptr.*;
            }
            pub inline fn nextPtr(self: *Self) ?*u8 {
                switch (comptime order) {
                    .row => {
                        if (self.col_index == self.view.numCols()) return null;
                        self.col_index += 1;
                        return self.view.getPtr(.{
                            .row = self.row_index,
                            .col = self.col_index - 1,
                        });
                    },
                    .col => {
                        if (self.row_index == self.view.numRows()) return null;
                        self.row_index += 1;
                        return self.view.getPtr(.{
                            .row = self.row_index - 1,
                            .col = self.col_index,
                        });
                    },
                }
            }
        };
    }
};

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
    try expectSegment(mat, .col, 0, &.{ 1, 0, 5 });
    try expectSegment(mat, .col, 1, &.{ 2, 4, 0 });

    mat.setCol(1, &.{ 7, 8, 9 });
    try expectSegment(mat, .col, 1, &.{ 7, 8, 9 });

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
    try expectSegment(mat, .col, 0, &.{ 1, 2, 3 });
    try expectSegment(mat, .col, 1, &.{ 4, 5, 6 });
    try expectSegment(mat, .col, 2, &.{ 7, 8, 9 });
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
    try expectSegment(mat, .row, 0, &.{ 1, 2, 3 });
    try expectSegment(mat, .row, 1, &.{ 4, 5, 6 });
    try expectSegment(mat, .row, 2, &.{ 7, 8, 9 });
}

test "rows and cols" {
    var mat = try Matrix.init(std.testing.allocator, 4, 3);
    defer mat.deinit(std.testing.allocator);

    mat.setRow(0, &.{ 1, 2, 3 });
    mat.setRow(1, &.{ 5, 6, 7 });
    mat.setRow(2, &.{ 9, 10, 11 });
    mat.setRow(3, &.{ 13, 14, 15 });
    try expectSegment(mat, .row, 0, &.{ 1, 2, 3 });
    try expectSegment(mat, .row, 1, &.{ 5, 6, 7 });
    try expectSegment(mat, .row, 2, &.{ 9, 10, 11 });
    try expectSegment(mat, .row, 3, &.{ 13, 14, 15 });

    mat.setCol(1, &.{ 4, 8, 12, 16 });
    try expectSegment(mat, .row, 0, &.{ 1, 4, 3 });
    try expectSegment(mat, .row, 1, &.{ 5, 8, 7 });
    try expectSegment(mat, .row, 2, &.{ 9, 12, 11 });
    try expectSegment(mat, .row, 3, &.{ 13, 16, 15 });

    try expectSegment(mat, .col, 0, &.{ 1, 5, 9, 13 });
    try expectSegment(mat, .col, 1, &.{ 4, 8, 12, 16 });
    try expectSegment(mat, .col, 2, &.{ 3, 7, 11, 15 });

    var m2 = try Matrix.init(std.testing.allocator, 3, 2);
    defer m2.deinit(std.testing.allocator);

    m2.setCol(0, &.{ 1, 3, 7 });
    m2.setCol(1, &.{ 2, 5, 2 });
    try expectSegment(m2, .col, 0, &.{ 1, 3, 7 });

    m2.setRow(1, &.{ 9, 8 });
    try expectSegment(m2, .row, 0, &.{ 1, 2 });
    try expectSegment(m2, .row, 1, &.{ 9, 8 });
    try expectSegment(m2, .row, 2, &.{ 7, 2 });
}

test subView {
    var mat = try Matrix.init(std.testing.allocator, 3, 3);
    defer mat.deinit(std.testing.allocator);

    mat.setRow(0, &.{ 1, 2, 3 });
    mat.setRow(1, &.{ 4, 5, 6 });
    mat.setRow(2, &.{ 7, 8, 9 });

    // non-exclusionary sub-view

    // exclusionary sub-views
    var submat = mat.subView(&.{0}, &.{});
    try std.testing.expectEqual(@as(u8, 2), submat.numRows());
    try std.testing.expectEqual(@as(u8, 3), submat.numCols());

    try expectSubSegment(submat, .row, 0, &.{ 4, 5, 6 });
    try expectSubSegment(submat, .row, 1, &.{ 7, 8, 9 });

    try expectSubSegment(submat, .col, 0, &.{ 4, 7 });
    try expectSubSegment(submat, .col, 1, &.{ 5, 8 });
    try expectSubSegment(submat, .col, 2, &.{ 6, 9 });

    submat = submat.subView(&.{}, &.{1});
    try std.testing.expectEqual(@as(u8, 2), submat.numRows());
    try std.testing.expectEqual(@as(u8, 2), submat.numCols());

    try expectSubSegment(submat, .row, 0, &.{ 4, 6 });
    try expectSubSegment(submat, .row, 1, &.{ 7, 9 });

    try expectSubSegment(submat, .col, 0, &.{ 4, 7 });
    try expectSubSegment(submat, .col, 1, &.{ 6, 9 });

    submat = mat.subView(&.{1}, &.{ 0, 2 });
    try std.testing.expectEqual(@as(u8, 2), submat.numRows());
    try std.testing.expectEqual(@as(u8, 1), submat.numCols());

    try expectSubSegment(submat, .row, 0, &.{2});
    try expectSubSegment(submat, .row, 1, &.{8});

    try expectSubSegment(submat, .col, 0, &.{ 2, 8 });

    // bigger matrix

    if (!mat.resizeAndReset(std.testing.allocator, 5, 5)) {
        mat.deinit(std.testing.allocator);
        mat = Matrix{};
        mat = try Matrix.init(std.testing.allocator, 5, 5);
    }

    // zig fmt: off
    //                 0   1   2   3   4
    mat.setRow(0, &.{  1,  2,  3,  4,  5 });
    mat.setRow(1, &.{  6,  7,  8,  9, 10 });
    mat.setRow(2, &.{ 11, 12, 13, 14, 15 });
    mat.setRow(3, &.{ 16, 17, 18, 19, 20 });
    mat.setRow(4, &.{ 21, 22, 23, 24, 25 });
    // zig fmt: on

    submat = mat.subView(&.{ 1, 3 }, &.{ 1, 3 });
    try std.testing.expectEqual(@as(u8, 3), submat.numRows());
    try std.testing.expectEqual(@as(u8, 3), submat.numCols());

    // zig fmt: off
    try expectSubSegment(submat, .row, 0, &.{  1,  3,  5 });
    try expectSubSegment(submat, .row, 1, &.{ 11, 13, 15 });
    try expectSubSegment(submat, .row, 2, &.{ 21, 23, 25 });
    // zig fmt: on

    try expectSubSegment(submat, .col, 0, &.{ 1, 11, 21 });
    try expectSubSegment(submat, .col, 1, &.{ 3, 13, 23 });
    try expectSubSegment(submat, .col, 2, &.{ 5, 15, 25 });

    submat = submat.subView(&.{0}, &.{});
    try std.testing.expectEqual(@as(u8, 2), submat.numRows());
    try std.testing.expectEqual(@as(u8, 3), submat.numCols());

    try expectSubSegment(submat, .row, 0, &.{ 11, 13, 15 });
    try expectSubSegment(submat, .row, 1, &.{ 21, 23, 25 });

    submat = submat.subView(&.{}, &.{0});
    try std.testing.expectEqual(@as(u8, 2), submat.numRows());
    try std.testing.expectEqual(@as(u8, 2), submat.numCols());

    try expectSubSegment(submat, .row, 0, &.{ 13, 15 });
    try expectSubSegment(submat, .row, 1, &.{ 23, 25 });

    submat = mat.subView(&.{0}, &.{});
    try std.testing.expectEqual(@as(u8, 4), submat.numRows());
    try std.testing.expectEqual(@as(u8, 5), submat.numCols());

    // zig fmt: off
    try expectSubSegment(submat, .row, 0, &.{  6,  7,  8,  9, 10 });
    try expectSubSegment(submat, .row, 1, &.{ 11, 12, 13, 14, 15 });
    try expectSubSegment(submat, .row, 2, &.{ 16, 17, 18, 19, 20 });
    try expectSubSegment(submat, .row, 3, &.{ 21, 22, 23, 24, 25 });
    // zig fmt: on
}

fn expectSegment(
    matrix: Matrix,
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

fn expectSubSegment(
    sub_view: SubView,
    comptime segment_order: enum { row, col },
    rc_idx: u8,
    expected_values: []const u8,
) !void {
    const actual_values = try std.testing.allocator.alloc(u8, switch (segment_order) {
        .row => sub_view.numCols(),
        .col => sub_view.numRows(),
    });
    defer std.testing.allocator.free(actual_values);
    @memset(actual_values, 0);

    var amt: usize = actual_values.len;

    var iter = switch (segment_order) {
        .row => sub_view.rowIterator(rc_idx),
        .col => sub_view.colIterator(rc_idx),
    };
    for (actual_values, 0..) |*actual, i| actual.* = iter.next() orelse {
        amt = i;
        break;
    };
    try std.testing.expectEqual(@as(?u8, null), iter.next());
    try std.testing.expectEqualSlices(u8, expected_values, actual_values[0..amt]);
}
