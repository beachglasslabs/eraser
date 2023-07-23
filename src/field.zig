// based on git@github.com:vishesh-khemani/erasure-coding
const std = @import("std");

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

        pub fn toVector(self: *const Self, allocator: std.mem.Allocator, a: u8) ![]u8 {
            var list = try std.ArrayList(u8).initCapacity(allocator, self.exp);
            defer list.deinit();
            for (0..self.exp) |i| {
                var j = (a >> @intCast(i)) & 1;
                list.appendAssumeCapacity(j);
            }
            return list.toOwnedSlice();
        }

        // n x n binary matrix representation
        pub fn toColMat(self: *const Self, allocator: std.mem.Allocator, a: usize) ![][]u8 {
            var list = try std.ArrayList([]u8).initCapacity(allocator, self.exp);
            defer list.deinit();
            var basis: u8 = 1;
            for (0..self.exp) |_| {
                var p = try self.mul(a, basis);
                basis <<= 1;
                list.appendAssumeCapacity(try self.toVector(allocator, p));
            }
            return list.toOwnedSlice();
        }

        // n x n binary matrix representation
        pub fn toMatrix(self: *const Self, allocator: std.mem.Allocator, a: usize) ![][]u8 {
            var list = try std.ArrayList([]u8).initCapacity(allocator, self.exp);
            defer list.deinit();
            var m = try self.toColMat(allocator, a);
            return transpose(m);
        }

        fn transpose(m: [][]u8) [][]u8 {
            for (0..m.len) |r| {
                for (0..m.len) |c| {
                    if (r == c) break;
                    var t = m[r][c];
                    m[r][c] = m[c][r];
                    m[c][r] = t;
                }
            }
            return m;
        }
    };
}
