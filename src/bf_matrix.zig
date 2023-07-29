// based on git@github.com:vishesh-khemani/erasure-coding
const std = @import("std");
const bff = @import("bf_field.zig");
const mat = @import("matrix.zig");

// matrix with elements in a 2^n finite field
pub fn BinaryFieldMatrix(comptime r: comptime_int, comptime c: comptime_int, comptime n: comptime_int) type {
    return struct {
        allocator: std.mem.Allocator,
        field: bff.BinaryFiniteField(n) = undefined,
        matrix: mat.Matrix(r, c) = undefined,

        const Self = @This();

        // 2^n field
        pub fn init(
            allocator: std.mem.Allocator,
        ) !Self {
            return .{
                .allocator = allocator,
                .field = try bff.BinaryFiniteField(n).init(),
                .matrix = try mat.Matrix(r, c).init(allocator, mat.DataOrder.row),
            };
        }

        pub fn initCauchy(
            allocator: std.mem.Allocator,
        ) !Self {
            var field = try bff.BinaryFiniteField(n).init();
            var matrix = try toCauchy(allocator, field);

            return .{
                .allocator = allocator,
                .field = field,
                .matrix = matrix,
            };
        }

        pub fn initMatrix(
            allocator: std.mem.Allocator,
            matrix: mat.Matrix(r, c),
        ) !Self {
            return .{
                .allocator = allocator,
                .field = try bff.BinaryFiniteField(n).init(),
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

        pub fn det(self: *const Self) !u8 {
            std.debug.assert(r == c);

            if (r == 1) {
                return self.matrix.get(0, 0);
            }

            var result: u8 = 0;
            inline for (0..c) |i| {
                var sub = try self.subMatrix(&[_]u8{0}, &[_]u8{i});
                defer sub.deinit();
                var x = try self.field.mul(self.matrix.get(0, i), try sub.det());
                if (c % 2 == 1) {
                    x = try self.field.neg(x);
                }
                result = try self.field.add(result, x);
            }
            return result;
        }

        fn toCauchy(allocator: std.mem.Allocator, field: bff.BinaryFiniteField(n)) !mat.Matrix(r, c) {
            std.debug.assert(field.order >= r + c);
            var m = try mat.Matrix(r, c).init(allocator, mat.DataOrder.row);
            for (0..r) |i| {
                for (0..c) |j| {
                    m.set(i, j, try field.invert(try field.sub(i + c, j)));
                }
            }
            return m;
        }

        pub fn print(self: *const Self) void {
            self.matrix.print();
        }

        pub fn subMatrix(self: *const Self, comptime excluded_rows: []const u8, comptime excluded_cols: []const u8) !BinaryFieldMatrix(r - excluded_rows.len, c - excluded_cols.len, n) {
            const sr = r - excluded_rows.len;
            const sc = c - excluded_cols.len;
            var m = try mat.Matrix(sr, sc).init(self.allocator, self.matrix.mtype);
            comptime var i = 0;
            rblk: inline for (0..r) |ri| {
                inline for (excluded_rows) |er| {
                    if (ri == er) {
                        continue :rblk;
                    }
                }
                comptime var j = 0;
                cblk: inline for (0..c) |ci| {
                    inline for (excluded_cols) |ec| {
                        if (ci == ec) {
                            continue :cblk;
                        }
                    }
                    m.set(i, j, self.matrix.get(ri, ci));
                    j += 1;
                }
                i += 1;
            }
            return try BinaryFieldMatrix(sr, sc, n).initMatrix(self.allocator, m);
        }
    };
}

test "cauchy matrix" {
    var cnm = try BinaryFieldMatrix(5, 3, 3).initCauchy(std.testing.allocator);
    defer cnm.deinit();
    cnm.print();
    var bfm = try BinaryFieldMatrix(3, 3, 2).init(std.testing.allocator);
    defer bfm.deinit();
    std.debug.print("det == {d}\n", .{try bfm.det()});
}
