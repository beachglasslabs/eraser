// based on git@github.com:vishesh-khemani/erasure-coding
const std = @import("std");
const assert = std.debug.assert;
const Matrix = @import("Matrix.zig");

const BinaryFiniteField = @This();
exp: Exp,
order: Order,
divisor: Divisor,

pub const Exp = u3;
const Order = u8;
const Divisor = u8;

/// 2^exp field
pub fn init(exp: Exp) error{InvalidExponent}!BinaryFiniteField {
    // Irreducible polynomail for mod multiplication
    const d: u8 = switch (exp) {
        0 => return error.InvalidExponent,
        1 => 3, //   1 + x ? undef  shift(0b11)       = 2
        2 => 7, //   1 + x + x^2    shift(0b111)      = 3
        3 => 11, //  1 + x + x^3    shift(0b1011)     = 4
        4 => 19, //  1 + x + x^4    shift(0b10011)    = 5
        5 => 37, //  1 + x^2 + x^5  shift(0b100101)   = 6
        6 => 67, //  1 + x + x^6    shift(0b1000011)  = 7
        7 => 131, // 1 + x + x^7    shift(0b10000011) = 8
    };

    return .{
        .exp = exp,
        .order = @as(u8, 1) << exp,
        .divisor = d,
    };
}

pub inline fn validate(self: BinaryFiniteField, number: anytype) error{InvalidNumber}!u8 {
    if (number >= self.order)
        return error.InvalidNumber;
    return @intCast(number);
}

pub fn add(self: BinaryFiniteField, a: anytype, b: anytype) error{InvalidNumber}!u8 {
    const valid_a = try self.validate(a);
    const valid_b = try self.validate(b);
    return self.validate(valid_a ^ valid_b) catch unreachable;
}

pub fn neg(self: BinaryFiniteField, a: usize) error{InvalidNumber}!u8 {
    return try self.validate(a);
}

pub fn sub(self: BinaryFiniteField, a: anytype, b: anytype) error{InvalidNumber}!u8 {
    const neg_b = try self.neg(b);
    return try self.add(a, neg_b);
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

pub fn mul(self: BinaryFiniteField, a: anytype, b: anytype) error{InvalidNumber}!u8 {
    if (self.exp == 1) {
        return self.validate(try self.validate(a) * try self.validate(b));
    }

    // n > 1
    const x = try self.validate(a);
    const y = try self.validate(b);
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
    return try self.validate(result);
}

pub fn invert(self: BinaryFiniteField, a: usize) error{ NoInverse, InvalidNumber }!u8 {
    if (try self.validate(a) == 0) {
        return error.NoInverse;
    }
    for (0..self.order) |b| {
        if (try self.mul(a, b) == 1) {
            return try self.validate(b);
        }
    }
    return error.NoInverse;
}

pub fn div(self: BinaryFiniteField, a: usize, b: usize) error{ NoInverse, InvalidNumber }!u8 {
    return try self.mul(a, try self.invert(b));
}

fn setCol(mat: *Matrix, c: usize, a: u8) void {
    for (0..mat.num_rows) |r| {
        const v = (a >> @intCast(r)) & 1;
        mat.set(.{ .row = @intCast(r), .col = @intCast(c) }, v);
    }
}

pub fn setAllCols(self: BinaryFiniteField, m: *Matrix, a: anytype) !void {
    assert(m.num_rows == m.num_cols);
    var basis: u8 = 1;
    for (0..m.num_rows) |c| {
        const p = try self.mul(a, basis);
        basis <<= 1;
        setCol(m, c, p);
    }
}

/// n x n binary matrix representation
pub fn toMatrix(self: BinaryFiniteField, allocator: std.mem.Allocator, a: anytype) !Matrix {
    var mat = try Matrix.init(allocator, self.exp, self.exp);
    errdefer mat.deinit(allocator);
    try self.setAllCols(&mat, a);
    return mat;
}

test "convert to matrix" {
    const bff = try BinaryFiniteField.init(3);

    var bfm = try bff.toMatrix(std.testing.allocator, 6);
    defer bfm.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, bfm.getSlice(0), &[_]u8{ 0, 1, 1 });
    try std.testing.expectEqualSlices(u8, bfm.getSlice(1), &[_]u8{ 1, 1, 0 });
    try std.testing.expectEqualSlices(u8, bfm.getSlice(2), &[_]u8{ 1, 1, 1 });
}
