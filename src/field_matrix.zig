// based on git@github.com:vishesh-khemani/erasure-coding
const std = @import("std");
const bff = @import("finite_field.zig");
const mat = @import("matrix.zig");
const math = @import("math.zig");

// matrix with elements in a 2^n finite field
pub fn BinaryFieldMatrix(comptime m: comptime_int, comptime n: comptime_int, comptime b: comptime_int) type {
    return struct {
        allocator: std.mem.Allocator = undefined,
        field: bff.BinaryFiniteField(b) = undefined,
        matrix: mat.Matrix(m, n) = undefined,
        comptime numRows: u8 = m,
        comptime numCols: u8 = n,

        const Self = @This();

        // 2^n field
        pub fn init(
            allocator: std.mem.Allocator,
        ) !Self {
            return .{
                .allocator = allocator,
                .field = try bff.BinaryFiniteField(b).init(),
                .matrix = try mat.Matrix(m, n).init(allocator, mat.DataOrder.row),
            };
        }

        pub fn initCauchy(
            allocator: std.mem.Allocator,
        ) !Self {
            const field = try bff.BinaryFiniteField(b).init();
            const matrix = try toCauchy(allocator, field);

            return .{
                .allocator = allocator,
                .field = field,
                .matrix = matrix,
            };
        }

        pub fn initMatrix(
            allocator: std.mem.Allocator,
            matrix: mat.Matrix(m, n),
        ) !Self {
            return .{
                .allocator = allocator,
                .field = try bff.BinaryFiniteField(b).init(),
                .matrix = matrix,
            };
        }

        pub fn deinit(self: *Self) void {
            self.matrix.deinit();
        }

        pub fn get(self: *const Self, r: usize, c: usize) u8 {
            return self.matrix.get(r, c);
        }

        pub fn det(self: *const Self) !u8 {
            std.debug.assert(m == n);

            if (m == 1) {
                return self.matrix.get(0, 0);
            }

            var result: u8 = 0;
            inline for (0..n) |c| {
                var sub = try self.subMatrix(1, 1, &[_]u8{0}, &[_]u8{c});
                defer sub.deinit();
                var x = try self.field.mul(self.matrix.get(0, c), try sub.det());
                if (c % 2 == 1) {
                    x = try self.field.neg(x);
                }
                result = try self.field.add(result, x);
            }
            return result;
        }

        fn toCauchy(allocator: std.mem.Allocator, field: bff.BinaryFiniteField(b)) !mat.Matrix(m, n) {
            std.debug.assert(field.order >= m + n);

            var cnm = try mat.Matrix(m, n).init(allocator, mat.DataOrder.row);
            for (0..m) |r| {
                for (0..n) |c| {
                    cnm.set(r, c, try field.invert(try field.sub(r + n, c)));
                }
            }
            return cnm;
        }

        pub fn format(self: *const Self, comptime fmt: []const u8, opts: std.fmt.FormatOptions, stream: anytype) !void {
            try self.matrix.format(fmt, opts, stream);
        }

        pub fn subMatrix(self: *const Self, comptime em: comptime_int, comptime en: comptime_int, excluded_rows: []const u8, excluded_cols: []const u8) !BinaryFieldMatrix(m - em, n - en, b) {
            std.debug.assert(em == excluded_rows.len);
            std.debug.assert(en == excluded_cols.len);
            var sub = try mat.Matrix(m - em, n - en).init(self.allocator, self.matrix.mtype);
            var i: usize = 0;
            rblk: for (0..m) |r| {
                for (excluded_rows) |er| {
                    if (r == er) {
                        continue :rblk;
                    }
                }
                var j: usize = 0;
                cblk: for (0..n) |c| {
                    for (excluded_cols) |ec| {
                        if (c == ec) {
                            continue :cblk;
                        }
                    }
                    sub.set(i, j, self.matrix.get(r, c));
                    j += 1;
                }
                i += 1;
            }
            return try BinaryFieldMatrix(m - em, n - en, b).initMatrix(self.allocator, sub);
        }

        pub fn cofactorize(self: *Self) !BinaryFieldMatrix(m, n, b) {
            std.debug.assert(m == n);

            var cof = try mat.Matrix(m, n).init(self.allocator, self.matrix.mtype);
            inline for (0..m) |r| {
                inline for (0..n) |c| {
                    var sub = try self.subMatrix(1, 1, &[_]u8{r}, &[_]u8{c});
                    defer sub.deinit();
                    cof.set(r, c, try sub.det());
                    if ((r + c) % 2 == 1) {
                        cof.set(r, c, try self.field.neg(cof.get(r, c)));
                    }
                }
            }
            return try BinaryFieldMatrix(m, n, b).initMatrix(self.allocator, cof);
        }

        pub fn transpose(self: *Self) void {
            std.debug.assert(m == n);

            self.matrix.transpose();
        }

        pub fn scale(self: *Self, factor: usize) !void {
            std.debug.assert(m == n);

            for (0..m) |r| {
                for (0..n) |c| {
                    self.matrix.set(r, c, try self.field.mul(self.matrix.get(r, c), factor));
                }
            }
        }

        pub fn invert(self: *Self) !BinaryFieldMatrix(m, n, b) {
            var imx = try self.cofactorize();
            imx.transpose();
            try imx.scale(try self.field.invert(try self.det()));
            return imx;
        }

        pub fn multiply(self: *Self, comptime z: comptime_int, other: BinaryFieldMatrix(n, z, b)) !BinaryFieldMatrix(m, z, b) {
            var matrix = try mat.Matrix(m, z).init(self.allocator, mat.DataOrder.row);
            for (0..m) |r| {
                for (0..z) |c| {
                    for (0..n) |i| {
                        matrix.set(r, c, try self.field.add(matrix.get(r, c), try self.field.mul(self.get(r, i), other.get(i, c))));
                    }
                }
            }
            return try BinaryFieldMatrix(m, z, b).initMatrix(self.allocator, matrix);
        }

        pub fn toBinary(self: *const Self) !BinaryFieldMatrix(m * b, n * b, 1) {
            var matrix = try mat.Matrix(m * b, n * b).init(self.allocator, mat.DataOrder.row);
            for (0..m) |r| {
                for (0..n) |c| {
                    const a = self.matrix.get(r, c);
                    var bfm = try self.field.toMatrix(self.allocator, a);
                    defer bfm.deinit();
                    for (0..b) |i| {
                        for (0..b) |j| {
                            matrix.set(r * b + i, c * b + j, try self.field.validated(bfm.get(i, j)));
                        }
                    }
                }
            }
            return try BinaryFieldMatrix(m * b, n * b, 1).initMatrix(self.allocator, matrix);
        }
    };
}

test "square matrix" {
    var field = try bff.BinaryFiniteField(3).init();
    var bfm = try BinaryFieldMatrix(3, 3, 3).initMatrix(std.testing.allocator, try field.toMatrix(std.testing.allocator, 5));
    defer bfm.deinit();
    var inverse = try bfm.invert();
    defer inverse.deinit();
}

test "matrix multiplication" {
    var bfma = try BinaryFieldMatrix(5, 3, 3).initCauchy(std.testing.allocator);
    defer bfma.deinit();
    var bfmb = try BinaryFieldMatrix(3, 4, 3).initCauchy(std.testing.allocator);
    defer bfmb.deinit();
    var bfmc = try bfma.multiply(4, bfmb);
    defer bfmc.deinit();
}

test "determinant" {
    var bfma = try BinaryFieldMatrix(2, 2, 2).initCauchy(std.testing.allocator);
    defer bfma.deinit();
    const deta = try bfma.det();
    try std.testing.expectEqual(deta, 1);
    var bfmb = try BinaryFieldMatrix(3, 3, 3).initCauchy(std.testing.allocator);
    defer bfmb.deinit();
    const detb = try bfmb.det();
    try std.testing.expectEqual(detb, 7);
    var bfmc = try BinaryFieldMatrix(4, 4, 4).initCauchy(std.testing.allocator);
    defer bfmc.deinit();
    const detc = try bfmc.det();
    try std.testing.expectEqual(detc, 7);
}

test "inverse" {
    var bfm = try BinaryFieldMatrix(5, 3, 3).initCauchy(std.testing.allocator);
    defer bfm.deinit();
    var sub = try bfm.subMatrix(2, 0, &[_]u8{ 0, 1 }, &[0]u8{});
    defer sub.deinit();
    var inv = try sub.invert();
    defer inv.deinit();
    std.debug.print("inv: {}\n", .{inv});
}

test "invertible sub-matrices" {
    const m = 5;
    const n = 3;
    var bfm = try BinaryFieldMatrix(m, n, 3).initCauchy(std.testing.allocator);
    defer bfm.deinit();
    comptime var ex_rows = math.choose(&[_]u8{ 0, 1, 2, 3, 4 }, m - n);
    std.debug.print("\nex_rows.len = {d}:\n", .{ex_rows.len});
    inline for (0..ex_rows.len) |i| {
        std.debug.print("ex_rows[{d}] = {any}\n", .{ i, ex_rows[i] });
        const er = ex_rows[i][0..(m - n)];
        var submatrix = try bfm.subMatrix(2, 0, er, &[0]u8{});
        defer submatrix.deinit();
        try std.testing.expectEqual(bfm.numRows - ex_rows[i].len, submatrix.numRows);
        try std.testing.expectEqual(bfm.numCols, submatrix.numCols);
        var inverse = try submatrix.invert();
        defer inverse.deinit();
        std.debug.print("inv: {}\n", .{inverse});
        var product1 = try inverse.multiply(submatrix.numCols, submatrix);
        defer product1.deinit();
        std.debug.print("p1: {}\n", .{product1});
        var product2 = try submatrix.multiply(inverse.numCols, inverse);
        defer product2.deinit();
        std.debug.print("p2: {}\n", .{product2});
        try std.testing.expectEqual(product1.numRows, product2.numRows);
        try std.testing.expectEqual(product1.numCols, product2.numCols);
        for (0..product1.numRows) |r| {
            for (0..product1.numCols) |c| {
                try std.testing.expectEqual(product1.get(r, c), product2.get(r, c));
                if (r == c) {
                    try std.testing.expectEqual(product1.get(r, c), 1);
                } else {
                    try std.testing.expectEqual(@as(u8, 0), product1.get(r, c));
                }
            }
        }
        var sub_bin = try submatrix.toBinary();
        defer sub_bin.deinit();
        try std.testing.expectEqual(submatrix.numRows * submatrix.field.exp, sub_bin.numRows);
        try std.testing.expectEqual(submatrix.numCols * submatrix.field.exp, sub_bin.numCols);
        var inv_bin = try inverse.toBinary();
        defer inv_bin.deinit();
        var pr1_bin = try inv_bin.multiply(sub_bin.numCols, sub_bin);
        defer pr1_bin.deinit();
        var pr2_bin = try sub_bin.multiply(inv_bin.numCols, inv_bin);
        defer pr2_bin.deinit();
        for (0..pr1_bin.numRows * pr1_bin.field.exp) |r| {
            for (0..pr1_bin.numCols * pr1_bin.field.exp) |c| {
                try std.testing.expectEqual(pr1_bin.get(r, c), pr2_bin.get(r, c));
                if (r == c) {
                    try std.testing.expectEqual(pr1_bin.get(r, c), 1);
                } else {
                    try std.testing.expectEqual(@as(u8, 0), pr1_bin.get(r, c));
                }
            }
        }
    }
}

test "matrix binary representation" {
    var bfma = try BinaryFieldMatrix(5, 3, 3).initCauchy(std.testing.allocator);
    defer bfma.deinit();
    for (0..bfma.field.order) |a| {
        var mat_a = try bfma.field.toMatrix(std.testing.allocator, a);
        defer mat_a.deinit();
        for (0..bfma.field.order) |b| {
            var mat_b = try bfma.field.toMatrix(std.testing.allocator, b);
            defer mat_b.deinit();
            const sum = try bfma.field.add(a, b);
            var mat_sum = try bfma.field.toMatrix(std.testing.allocator, sum);
            defer mat_sum.deinit();
            for (0..mat_a.numRows) |r| {
                for (0..mat_a.numCols) |c| {
                    try std.testing.expectEqual(mat_sum.get(r, c), try bfma.field.add(mat_a.get(r, c), mat_b.get(r, c)));
                }
            }
        }
    }
}
