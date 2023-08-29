//! matrix with elements in a 2^n finite field
// based on git@github.com:vishesh-khemani/erasure-coding
const std = @import("std");
const assert = std.debug.assert;

const util = @import("util.zig");
const BinaryFiniteField = @import("BinaryFiniteField.zig");
const Matrix = @import("Matrix.zig");
const mulWide = std.math.mulWide;

const BinaryFieldMatrix = @This();
field: BinaryFiniteField,
matrix: Matrix,

/// 2^n field
pub fn init(allocator: std.mem.Allocator, rows: u8, cols: u8, exp: BinaryFiniteField.Exp) !BinaryFieldMatrix {
    var matrix = try Matrix.init(allocator, rows, cols);
    defer matrix.deinit(allocator);

    const field = try BinaryFiniteField.init(exp);
    return .{
        .field = field,
        .matrix = matrix.move(),
    };
}

pub fn initCauchy(allocator: std.mem.Allocator, rows: u8, cols: u8, exp: BinaryFiniteField.Exp) !BinaryFieldMatrix {
    const field = try BinaryFiniteField.init(exp);

    const matrix: Matrix = try toCauchy(allocator, field, rows, cols);
    errdefer matrix.deinit(allocator);

    return .{
        .field = field,
        .matrix = matrix,
    };
}

pub fn initMatrix(matrix: Matrix, b: BinaryFiniteField.Exp) !BinaryFieldMatrix {
    return .{
        .field = try BinaryFiniteField.init(b),
        .matrix = matrix,
    };
}

pub fn clone(self: BinaryFieldMatrix, allocator: std.mem.Allocator) !BinaryFieldMatrix {
    return .{
        .field = self.field,
        .matrix = try self.matrix.clone(allocator),
    };
}

pub fn cloneWith(self: BinaryFieldMatrix, data: []align(16) u8) BinaryFieldMatrix {
    return .{
        .field = self.field,
        .matrix = self.matrix.cloneWith(data),
    };
}

pub fn deinit(self: BinaryFieldMatrix, allocator: std.mem.Allocator) void {
    self.matrix.deinit(allocator);
}

pub inline fn numRows(self: BinaryFieldMatrix) u8 {
    return self.matrix.num_rows;
}
pub inline fn numCols(self: BinaryFieldMatrix) u8 {
    return self.matrix.num_cols;
}

pub inline fn getPtr(self: BinaryFieldMatrix, idx: Matrix.CellIndex) *u8 {
    return self.matrix.getPtr(idx);
}
pub inline fn get(self: BinaryFieldMatrix, idx: Matrix.CellIndex) u8 {
    return self.matrix.get(idx);
}
pub inline fn set(self: BinaryFieldMatrix, idx: Matrix.CellIndex, value: u8) u8 {
    return self.matrix.set(idx, value);
}

pub inline fn det(self: BinaryFieldMatrix) !u8 {
    var view = self.matrix.subView(&.{}, &.{});
    return viewDet(self.field, &view);
}

fn viewDet(field: BinaryFiniteField, view: *const Matrix.SubView) !u8 {
    assert(view.numRows() == view.numCols());

    // inline the simplest cases
    switch (view.numRows()) {
        1 => return view.get(.{ .row = 0, .col = 0 }),
        2 => {
            const a = view.get(.{ .row = 0, .col = 0 });
            const b = view.get(.{ .row = 0, .col = 1 });
            const c = view.get(.{ .row = 1, .col = 0 });
            const d = view.get(.{ .row = 1, .col = 1 });
            return try field.sub(try field.mul(a, d), try field.mul(b, c));
        },
        3 => {
            const a = view.get(.{ .row = 0, .col = 0 });
            const b = view.get(.{ .row = 0, .col = 1 });
            const c = view.get(.{ .row = 0, .col = 2 });

            const d = view.get(.{ .row = 1, .col = 0 });
            const e = view.get(.{ .row = 1, .col = 1 });
            const f = view.get(.{ .row = 1, .col = 2 });

            const g = view.get(.{ .row = 2, .col = 0 });
            const h = view.get(.{ .row = 2, .col = 1 });
            const i = view.get(.{ .row = 2, .col = 2 });

            const ei_fh = try field.sub(try field.mul(e, i), try field.mul(f, h));
            const di_fg = try field.sub(try field.mul(d, i), try field.mul(f, g));
            const dh_eg = try field.sub(try field.mul(d, h), try field.mul(e, g));

            return try field.add(
                try field.sub(try field.mul(a, ei_fh), try field.mul(b, di_fg)),
                try field.mul(c, dh_eg),
            );
        },
        else => {},
    }

    var result: u8 = 0;
    for (0..view.numCols()) |c| {
        const sub = view.subView(&[_]u8{0}, &[_]u8{@intCast(c)});
        const sub_det = try viewDet(field, &sub);
        var x = try field.mul(view.get(.{ .row = 0, .col = @intCast(c) }), sub_det);
        if (c % 2 == 1) {
            x = try field.neg(x);
        }
        result = try field.add(result, x);
    }

    return result;
}

fn toCauchy(allocator: std.mem.Allocator, field: BinaryFiniteField, rows: u8, cols: u8) !Matrix {
    assert(field.order >= rows + cols);

    var cnm = try Matrix.init(allocator, rows, cols);
    errdefer cnm.deinit(allocator);

    for (0..rows) |m_i| {
        for (0..cols) |n_i| {
            const idx: Matrix.CellIndex = .{ .row = @intCast(m_i), .col = @intCast(n_i) };
            const inverted = try field.invert(try field.sub(m_i + cols, n_i));
            cnm.set(idx, inverted);
        }
    }

    return cnm;
}

pub fn format(
    self: BinaryFieldMatrix,
    comptime fmt: []const u8,
    opts: std.fmt.FormatOptions,
    stream: anytype,
) !void {
    try self.matrix.format(fmt, opts, stream);
}

pub const IndexSet = std.bit_set.ArrayBitSet(u32, 255);

pub fn subMatrix(
    self: BinaryFieldMatrix,
    allocator: std.mem.Allocator,
    excluded_rows: IndexSet,
    excluded_cols: IndexSet,
) !BinaryFieldMatrix {
    const data = try allocator.alignedAlloc(u8, 16, self.subMatrixCellCount(excluded_rows, excluded_cols));
    errdefer allocator.free(data);
    return self.subMatrixWith(data, excluded_rows, excluded_cols);
}
pub fn subMatrixWith(
    self: BinaryFieldMatrix,
    data: []align(16) u8,
    excluded_rows: IndexSet,
    excluded_cols: IndexSet,
) BinaryFieldMatrix {
    assert(data.len == self.subMatrixCellCount(excluded_rows, excluded_cols));
    assert(excluded_rows.count() < self.numRows());
    assert(excluded_cols.count() < self.numCols());

    const sub_view: Matrix.SubView = .{
        .parent = &self.matrix,
        .excluded_rows = excluded_rows,
        .excluded_cols = excluded_cols,
    };

    const sub_mat = Matrix.initWith(data, sub_view.numRows(), sub_view.numCols());
    sub_view.copyInto(sub_mat);
    return .{
        .matrix = sub_mat,
        .field = self.field,
    };
}
pub fn subMatrixCellCount(
    self: BinaryFieldMatrix,
    excluded_rows: IndexSet,
    excluded_cols: IndexSet,
) u16 {
    return Matrix.SubView.getCellCount(.{
        .parent = &self.matrix,
        .excluded_rows = excluded_rows,
        .excluded_cols = excluded_cols,
    });
}

pub fn cofactorize(self: BinaryFieldMatrix, allocator: std.mem.Allocator) !BinaryFieldMatrix {
    assert(self.numRows() == self.numCols());
    const data = try allocator.alignedAlloc(u8, 16, self.matrix.getCellCount());
    errdefer allocator.free(data);
    return try self.cofactorizeWith(data);
}

pub fn cofactorizeWith(self: BinaryFieldMatrix, data: []align(16) u8) !BinaryFieldMatrix {
    assert(self.numRows() == self.numCols());
    var result = Matrix.initWith(data, self.numRows(), self.numCols());

    for (0..result.numRows()) |row_idx| {
        for (0..result.numCols()) |col_idx| {
            const idx: Matrix.CellIndex = .{
                .row = @intCast(row_idx),
                .col = @intCast(col_idx),
            };

            const sub = self.matrix.subView(&.{idx.row}, &.{idx.col});
            var sub_det = try viewDet(self.field, &sub);
            if ((row_idx + col_idx) % 2 == 1) {
                sub_det = try self.field.neg(sub_det);
            }

            result.set(idx, sub_det);
        }
    }

    return .{
        .matrix = result,
        .field = self.field,
    };
}

pub inline fn transpose(self: *BinaryFieldMatrix) void {
    assert(self.numRows() == self.numCols());
    self.matrix.transpose();
}

pub fn scale(self: *BinaryFieldMatrix, factor: u8) !void {
    assert(self.numRows() == self.numCols());

    for (0..self.numRows()) |r| {
        for (0..self.numCols()) |c| {
            const idx: Matrix.CellIndex = .{ .row = @intCast(r), .col = @intCast(c) };
            const multiplied = try self.field.mul(self.matrix.get(idx), factor);
            self.matrix.set(idx, multiplied);
        }
    }
}

pub fn invert(self: BinaryFieldMatrix, allocator: std.mem.Allocator) !BinaryFieldMatrix {
    const data = try allocator.alignedAlloc(u8, 16, self.matrix.getCellCount());
    errdefer allocator.free(data);
    return try self.invertWith(data);
}
pub fn invertWith(self: BinaryFieldMatrix, data: []align(16) u8) !BinaryFieldMatrix {
    var imx = try self.cofactorizeWith(data);
    imx.transpose();

    const determinant = try self.det();
    try imx.scale(try self.field.invert(determinant));
    return imx;
}

pub fn toBinary(self: BinaryFieldMatrix, allocator: std.mem.Allocator) !BinaryFieldMatrix {
    const tmp_buf = try allocator.alignedAlloc(u8, 16, self.toBinaryTempBufCellCount());
    defer allocator.free(tmp_buf);

    const mat_buf = try allocator.alignedAlloc(u8, 16, self.toBinaryCellCount());
    errdefer allocator.free(mat_buf);

    return self.toBinaryWith(mat_buf, tmp_buf);
}

pub fn toBinaryTempBufCellCount(self: BinaryFieldMatrix) u16 {
    return mulWide(u8, self.field.exp, self.field.exp);
}
pub fn toBinaryCellCount(self: BinaryFieldMatrix) u16 {
    return self.matrix.getCellCount() *
        mulWide(BinaryFiniteField.Exp, self.field.exp, self.field.exp);
}
pub fn toBinaryWith(
    self: BinaryFieldMatrix,
    /// the backing buffer that will be used for the matrix in the returned binary field matrix
    mat_buf: []align(16) u8,
    tmp_buf: []align(16) u8,
) !BinaryFieldMatrix {
    var matrix = Matrix.initWith(mat_buf, self.numRows() * self.field.exp, self.numCols() * self.field.exp);

    var bfm = Matrix.initWith(tmp_buf, self.field.exp, self.field.exp);

    for (0..self.numRows()) |r| {
        for (0..self.numCols()) |c| {
            const a = self.matrix.get(.{ .row = @intCast(r), .col = @intCast(c) });
            try self.field.setAllCols(&bfm, a);

            for (0..self.field.exp) |i| {
                for (0..self.field.exp) |j| {
                    const dst_idx: Matrix.CellIndex = .{
                        .row = @intCast(r * self.field.exp + i),
                        .col = @intCast(c * self.field.exp + j),
                    };
                    const src = try self.field.validate(bfm.get(.{ .row = @intCast(i), .col = @intCast(j) }));
                    matrix.set(dst_idx, src);
                }
            }
        }
    }

    return try BinaryFieldMatrix.initMatrix(matrix, 1);
}

/// As of right now this is only used to ensure
/// that matrices are invertible in tests.
fn multiply(
    self: BinaryFieldMatrix,
    allocator: std.mem.Allocator,
    z: u8,
    other: BinaryFieldMatrix,
) !BinaryFieldMatrix {
    var matrix = try Matrix.init(allocator, self.numRows(), z);
    errdefer matrix.deinit(allocator);

    for (0..matrix.numRows()) |row_idx| {
        for (0..matrix.numCols()) |col_idx| {
            for (0..self.numCols()) |i| {
                const idx: Matrix.CellIndex = .{ .row = @intCast(row_idx), .col = @intCast(col_idx) };

                const multiplied = try self.field.mul(
                    self.get(.{ .row = idx.row, .col = @intCast(i) }),
                    other.get(.{ .row = @intCast(i), .col = idx.col }),
                );
                const added = try self.field.add(matrix.get(idx), multiplied);
                matrix.set(idx, added);
            }
        }
    }

    return .{
        .matrix = matrix,
        .field = self.field,
    };
}

test "square matrix" {
    const field = try BinaryFiniteField.init(3);

    var bfm = try BinaryFieldMatrix.initMatrix(try field.toMatrix(std.testing.allocator, 5), 3);
    defer bfm.deinit(std.testing.allocator);

    var inverse = try bfm.invert(std.testing.allocator);
    defer inverse.deinit(std.testing.allocator);
}

test "matrix multiplication" {
    var bfma = try BinaryFieldMatrix.initCauchy(std.testing.allocator, 5, 3, 3);
    defer bfma.deinit(std.testing.allocator);

    var bfmb = try BinaryFieldMatrix.initCauchy(std.testing.allocator, 3, 4, 3);
    defer bfmb.deinit(std.testing.allocator);

    var bfmc = try bfma.multiply(std.testing.allocator, 4, bfmb);
    defer bfmc.deinit(std.testing.allocator);
}

test "invertible sub-matrices" {
    const rows = 5;
    const cols = 3;

    var bfm = try BinaryFieldMatrix.initCauchy(std.testing.allocator, rows, cols, 3);
    defer bfm.deinit(std.testing.allocator);

    inline for (util.choose(&.{ 0, 1, 2, 3, 4 }, rows - cols)) |excluded_rows| {
        comptime var ex_rows = IndexSet.initEmpty();
        comptime for (excluded_rows) |ex_row| ex_rows.set(ex_row);

        var submatrix = try bfm.subMatrix(std.testing.allocator, ex_rows, IndexSet.initEmpty());
        defer submatrix.deinit(std.testing.allocator);

        try std.testing.expectEqual(bfm.numRows() - ex_rows.count(), submatrix.numRows());
        try std.testing.expectEqual(bfm.numCols(), submatrix.numCols());

        var inverse = try submatrix.invert(std.testing.allocator);
        defer inverse.deinit(std.testing.allocator);

        var product1 = try inverse.multiply(std.testing.allocator, submatrix.numCols(), submatrix);
        defer product1.deinit(std.testing.allocator);

        var product2 = try submatrix.multiply(std.testing.allocator, inverse.numCols(), inverse);
        defer product2.deinit(std.testing.allocator);

        try std.testing.expectEqual(product1.numRows(), product2.numRows());
        try std.testing.expectEqual(product1.numCols(), product2.numCols());
        for (0..product1.numRows()) |r| {
            for (0..product1.numCols()) |c| {
                const idx: Matrix.CellIndex = .{ .row = @intCast(r), .col = @intCast(c) };
                try std.testing.expectEqual(product1.get(idx), product2.get(idx));
                if (r == c) {
                    try std.testing.expectEqual(product1.get(idx), 1);
                } else {
                    try std.testing.expectEqual(@as(u8, 0), product1.get(idx));
                }
            }
        }
        var sub_bin = try submatrix.toBinary(std.testing.allocator);
        defer sub_bin.deinit(std.testing.allocator);

        try std.testing.expectEqual(mulWide(u8, submatrix.numRows(), submatrix.field.exp), sub_bin.numRows());
        try std.testing.expectEqual(mulWide(u8, submatrix.numCols(), submatrix.field.exp), sub_bin.numCols());

        var inv_bin = try inverse.toBinary(std.testing.allocator);
        defer inv_bin.deinit(std.testing.allocator);

        var pr1_bin = try inv_bin.multiply(std.testing.allocator, sub_bin.numCols(), sub_bin);
        defer pr1_bin.deinit(std.testing.allocator);

        var pr2_bin = try sub_bin.multiply(std.testing.allocator, inv_bin.numCols(), inv_bin);
        defer pr2_bin.deinit(std.testing.allocator);

        for (0..pr1_bin.numRows() * pr1_bin.field.exp) |r| {
            for (0..pr1_bin.numCols() * pr1_bin.field.exp) |c| {
                const idx: Matrix.CellIndex = .{ .row = @intCast(r), .col = @intCast(c) };

                try std.testing.expectEqual(pr1_bin.get(idx), pr2_bin.get(idx));
                if (r == c) {
                    try std.testing.expectEqual(pr1_bin.get(idx), 1);
                } else {
                    try std.testing.expectEqual(@as(u8, 0), pr1_bin.get(idx));
                }
            }
        }
    }
}

test "matrix binary representation" {
    var bfma = try BinaryFieldMatrix.initCauchy(std.testing.allocator, 5, 3, 3);
    defer bfma.deinit(std.testing.allocator);

    for (0..bfma.field.order) |a| {
        var mat_a = try bfma.field.toMatrix(std.testing.allocator, a);
        defer mat_a.deinit(std.testing.allocator);

        for (0..bfma.field.order) |b| {
            var mat_b = try bfma.field.toMatrix(std.testing.allocator, b);
            defer mat_b.deinit(std.testing.allocator);

            const sum = try bfma.field.add(a, b);

            var mat_sum = try bfma.field.toMatrix(std.testing.allocator, sum);
            defer mat_sum.deinit(std.testing.allocator);

            for (0..mat_a.numRows()) |r| {
                for (0..mat_a.num_cols) |c| {
                    const idx: Matrix.CellIndex = .{ .row = @intCast(r), .col = @intCast(c) };
                    try std.testing.expectEqual(mat_sum.get(idx), try bfma.field.add(mat_a.get(idx), mat_b.get(idx)));
                }
            }
        }
    }
}
