// based on git@github.com:vishesh-khemani/erasure-coding
const std = @import("std");
const bff = @import("bf_field.zig");
const Matrix = @import("matrix.zig");

// matrix with elements in a 2^n finite field
pub fn BinaryFiniteMatrix(comptime n: comptime_int) type {
    return struct {
        allocator: std.mem.Allocator,
        field: bff.BinaryFiniteField(n) = undefined,

        pub const Vec = @Vector(n, u8);

        const Self = @This();

        // 2^n field
        pub fn init(
            allocator: std.mem.Allocator,
        ) !Self {
            return .{
                .allocator = allocator,
                .field = try bff.BinaryFiniteField(n).init(),
            };
        }

        fn setCol(m: *Matrix, c: usize, a: u8) void {
            for (0..n) |r| {
                var v = (a >> @intCast(r)) & 1;
                m.set(r, c, v);
            }
        }

        fn setAllCols(self: *const Self, m: *Matrix, a: usize) !void {
            var basis: u8 = 1;
            for (0..n) |c| {
                var p = try self.field.mul(a, basis);
                basis <<= 1;
                setCol(m, c, p);
            }
        }

        // n x n binary matrix representation
        pub fn toColMat(self: *const Self, a: usize) !Matrix {
            var m = try Matrix.init(self.allocator, Matrix.DataOrder.col, n, n);
            try self.setAllCols(&m, a);
            return m;
        }

        // n x n binary matrix representation
        pub fn toMatrix(self: *const Self, a: usize) !Matrix {
            var m = try Matrix.init(self.allocator, Matrix.DataOrder.row, n, n);
            try self.setAllCols(&m, a);
            return m;
        }

        pub fn simdVector(self: *const Self, a: u8) !Vec {
            var list = try std.ArrayList(u8).initCapacity(self.allocator, n);
            defer list.deinit();
            inline for (0..n) |i| {
                var j = (a >> @intCast(i)) & 1;
                list.appendAssumeCapacity(j);
            }
            return list.items[0..n].*;
        }

        pub fn simdColMat(self: *const Self, a: usize) ![]Vec {
            var list = try std.ArrayList(Vec).initCapacity(self.allocator, n);
            defer list.deinit();
            var basis: u8 = 1;
            for (0..n) |_| {
                var p = try self.field.mul(a, basis);
                basis <<= 1;
                list.appendAssumeCapacity(try self.simdVector(p));
            }
            return list.toOwnedSlice();
        }

        pub fn simdRowMat(self: *const Self, a: usize) ![]Vec {
            var m = try self.toMatrix(a);
            defer m.deinit();
            var list = try std.ArrayList(Vec).initCapacity(self.allocator, n);
            defer list.deinit();
            for (0..n) |r| {
                var row = try m.getRow(r);
                defer self.allocator.free(row);
                list.appendAssumeCapacity(row[0..n].*);
            }
            return list.toOwnedSlice();
        }
    };
}
