// based on git@github.com:vishesh-khemani/erasure-coding
const std = @import("std");
const bff = @import("bf_field.zig");
const mat = @import("matrix.zig");

// matrix with elements in a 2^n finite field
pub fn BinaryFieldMatrix(comptime m: comptime_int, comptime n: comptime_int, comptime b: comptime_int) type {
    return struct {
        allocator: std.mem.Allocator,
        field: bff.BinaryFiniteField(b) = undefined,
        matrix: mat.Matrix(m, n) = undefined,

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
            var field = try bff.BinaryFiniteField(b).init();
            var matrix = try toCauchy(allocator, field);

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

        pub fn numRows(self: *const Self) u8 {
            return self.matrix.numRows();
        }

        pub fn numCols(self: *const Self) u8 {
            return self.matrix.numCols();
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
                var sub = try self.subMatrix(&[_]usize{0}, &[_]usize{c});
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

            var cauchy = try mat.Matrix(m, n).init(allocator, mat.DataOrder.row);
            for (0..n) |r| {
                for (0..n) |c| {
                    cauchy.set(r, c, try field.invert(try field.sub(r + n, c)));
                }
            }
            return cauchy;
        }

        pub fn print(self: *const Self) void {
            self.matrix.print();
        }

        pub fn subMatrix(self: *const Self, comptime excluded_rows: []const usize, comptime excluded_cols: []const usize) !BinaryFieldMatrix(m - excluded_rows.len, n - excluded_cols.len, b) {
            const sm = m - excluded_rows.len;
            const sn = n - excluded_cols.len;
            var sub = try mat.Matrix(sm, sn).init(self.allocator, self.matrix.mtype);
            comptime var i = 0;
            rblk: inline for (0..m) |r| {
                inline for (excluded_rows) |er| {
                    if (r == er) {
                        continue :rblk;
                    }
                }
                comptime var j = 0;
                cblk: inline for (0..n) |c| {
                    inline for (excluded_cols) |ec| {
                        if (c == ec) {
                            continue :cblk;
                        }
                    }
                    sub.set(i, j, self.matrix.get(r, c));
                    j += 1;
                }
                i += 1;
            }
            return try BinaryFieldMatrix(sm, sn, b).initMatrix(self.allocator, sub);
        }

        pub fn cofactorize(self: *Self) !void {
            std.debug.assert(m == n);

            inline for (0..m) |r| {
                inline for (0..n) |c| {
                    var sub = try self.subMatrix(&[_]usize{r}, &[_]usize{c});
                    defer sub.deinit();
                    self.matrix.set(r, c, try sub.det());
                    if ((r + c) % 2 == 1) {
                        self.matrix.set(r, c, try self.field.neg(self.matrix.get(r, c)));
                    }
                }
            }
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

        pub fn invert(self: *Self) !void {
            try self.cofactorize();
            self.transpose();
            try self.scale(try self.field.invert(try self.det()));
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
    };
}

test "cauchy matrix" {
    var cnm = try BinaryFieldMatrix(5, 3, 3).initCauchy(std.testing.allocator);
    defer cnm.deinit();
    cnm.print();
}

test "square matrix" {
    var field = try bff.BinaryFiniteField(3).init();
    var bfm = try BinaryFieldMatrix(3, 3, 3).initMatrix(std.testing.allocator, try field.toMatrix(std.testing.allocator, 5));
    defer bfm.deinit();
    bfm.print();
    std.debug.print("det == {d}\n", .{try bfm.det()});
    try bfm.invert();
    bfm.print();
}

test "matrix multiplication" {
    var bfma = try BinaryFieldMatrix(5, 3, 3).init(std.testing.allocator);
    defer bfma.deinit();
    var bfmb = try BinaryFieldMatrix(3, 4, 3).init(std.testing.allocator);
    defer bfmb.deinit();
    var bfmc = try bfma.multiply(4, bfmb);
    defer bfmc.deinit();
    bfmc.print();
}
