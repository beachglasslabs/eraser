// based on git@github.com:vishesh-khemani/erasure-coding
const std = @import("std");
const mat = @import("matrix.zig");

pub fn BinaryFiniteField(comptime n: comptime_int) type {
    return struct {
        exp: u8 = undefined,
        order: u8 = undefined,
        divisor: u8 = undefined,

        pub const Vec = @Vector(n, u8);

        pub const ValueError = error{
            InvalidExponentError,
            InvalidNumberError,
            NoInverseError,
        };

        const Self = @This();

        // 2^n field
        pub fn init() ValueError!Self {
            var d: u8 = undefined;

            // Irreducible polynomail for mod multiplication
            d = switch (n) {
                1 => 3, // 1 + x ? undef  shift(0b11)=2
                2 => 7, // 1 + x + x^2    shift(0b111)=3
                3 => 11, // 1 + x + x^3   shift(0b1011)=4
                4 => 19, // 1 + x + x^4   shift(0b10011)=5
                5 => 37, // 1 + x^2 + x^5 shift(0b100101)=6
                6 => 67, // 1 + x + x^6   shift(0b1000011)=7
                7 => 131, // 1 + x + x^7  shift(0b10000011)=8
                else => return ValueError.InvalidExponentError,
            };

            return .{
                .exp = @intCast(n),
                .divisor = d,
                .order = @as(u8, 1) << @intCast(n),
            };
        }

        pub fn order(self: *const Self) u8 {
            return self.order;
        }

        pub fn validated(self: *const Self, a: usize) ValueError!u8 {
            if (a < self.order) {
                return @intCast(a);
            } else {
                return ValueError.InvalidNumberError;
            }
        }

        pub fn add(self: *const Self, a: usize, b: usize) ValueError!u8 {
            return try self.validated((try self.validated(a)) ^ (try self.validated(b)));
        }

        pub fn neg(self: *const Self, a: usize) ValueError!u8 {
            return try self.validated(a);
        }

        pub fn sub(self: *const Self, a: usize, b: usize) ValueError!u8 {
            return try self.add(a, try self.neg(b));
        }

        fn countBits(num: usize) u8 {
            var v = num;
            var c: u8 = 0;
            while (v != 0) {
                v >>= 1;
                c += 1;
            }
            return c;
        }

        pub fn mul(self: *const Self, a: usize, b: usize) ValueError!u8 {
            if (self.exp == 1) {
                return self.validated(try self.validated(a) * try self.validated(b));
            }

            // n > 1
            const x = try self.validated(a);
            const y = try self.validated(b);
            var result: u16 = 0;
            for (0..8) |i| {
                const j = 7 - i;
                if (((y >> @intCast(j)) & 1) == 1) {
                    result ^= @as(u16, x) << @intCast(j);
                }
            }
            while (result >= self.order) {
                // count how many binary digits result has
                var j = countBits(result);
                j -= self.exp + 1;
                result ^= @as(u16, self.divisor) << @intCast(j);
            }
            return try self.validated(result);
        }

        pub fn invert(self: *const Self, a: usize) ValueError!u8 {
            if (try self.validated(a) == 0) {
                return ValueError.NoInverseError;
            }
            for (0..self.order) |b| {
                if (try self.mul(a, b) == 1) {
                    return try self.validated(b);
                }
            }
            return ValueError.NoInverseError;
        }

        pub fn div(self: *const Self, a: usize, b: usize) ValueError!u8 {
            return try self.mul(a, try self.invert(b));
        }

        fn setCol(m: *mat.Matrix(n, n), c: usize, a: u8) void {
            for (0..n) |r| {
                const v = (a >> @intCast(r)) & 1;
                m.set(r, c, v);
            }
        }

        fn setAllCols(self: *const Self, m: *mat.Matrix(n, n), a: usize) !void {
            var basis: u8 = 1;
            for (0..n) |c| {
                const p = try self.mul(a, basis);
                basis <<= 1;
                setCol(m, c, p);
            }
        }

        // n x n binary matrix representation
        pub fn toMatrix(self: *const Self, allocator: std.mem.Allocator, a: usize) !mat.Matrix(n, n) {
            var m = try mat.Matrix(n, n).init(allocator, mat.DataOrder.row);
            try self.setAllCols(&m, a);
            return m;
        }
    };
}

test "convert to matrix" {
    const bff = try BinaryFiniteField(3).init();
    var bfm = try bff.toMatrix(std.testing.allocator, 6);
    defer bfm.deinit();
    try std.testing.expectEqualSlices(u8, bfm.getSlice(0), &[_]u8{ 0, 1, 1 });
    try std.testing.expectEqualSlices(u8, bfm.getSlice(1), &[_]u8{ 1, 1, 0 });
    try std.testing.expectEqualSlices(u8, bfm.getSlice(2), &[_]u8{ 1, 1, 1 });
}
