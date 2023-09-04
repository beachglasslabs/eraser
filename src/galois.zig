const std = @import("std");
const assert = std.debug.assert;
const mulWide = std.math.mulWide;

const Matrix = @import("Matrix.zig");
const BinaryFieldMatrix = @import("BinaryFieldMatrix.zig");

const galois = @import("galois.zig");

pub const BinaryField = enum(u3) {
    degree1 = 1,
    degree2,
    degree3,
    degree4,
    degree5,
    degree6,
    degree7 = 7,

    /// 1...7
    pub const Exp = @typeInfo(BinaryField).Enum.tag_type;
    /// 2...128
    pub const Order = u8;
    /// 3, 7, 11, 19, 37, 67, 131
    pub const Divisor = u8;

    pub const InitError = error{InvalidExponent};
    pub const ValidateError = error{InvalidNumber};
    pub const InvertError = error{NoInverse};
    pub const OpError = ValidateError || InvertError;

    /// 2^exp field
    pub fn init(exp: Exp) InitError!BinaryField {
        return switch (exp) {
            1...7 => @enumFromInt(exp),
            else => error.InvalidExponent,
        };
    }

    pub inline fn exponent(self: BinaryField) Exp {
        return @intFromEnum(self);
    }
    pub inline fn order(self: BinaryField) Order {
        return @as(Order, 1) << self.exponent();
    }
    pub inline fn divisor(self: BinaryField) Divisor {
        // Irreducible polynomail for mod multiplication
        const Lut = std.EnumArray(BinaryField, Divisor);
        const lut: Lut = comptime Lut.init(.{
            .degree1 = 3, //   1 + x ? undef  shift(0b11)       = 2
            .degree2 = 7, //   1 + x + x^2    shift(0b111)      = 3
            .degree3 = 11, //  1 + x + x^3    shift(0b1011)     = 4
            .degree4 = 19, //  1 + x + x^4    shift(0b10011)    = 5
            .degree5 = 37, //  1 + x^2 + x^5  shift(0b100101)   = 6
            .degree6 = 67, //  1 + x + x^6    shift(0b1000011)  = 7
            .degree7 = 131, // 1 + x + x^7    shift(0b10000011) = 8
        });
        return lut.get(self);
    }

    pub inline fn validate(self: BinaryField, number: u8) ValidateError!u8 {
        if (number >= self.order())
            return error.InvalidNumber;
        return @intCast(number);
    }

    pub fn add(self: BinaryField, a: u8, b: u8) ValidateError!u8 {
        const valid_a = try self.validate(a);
        const valid_b = try self.validate(b);
        return self.validate(valid_a ^ valid_b) catch unreachable;
    }

    pub fn neg(self: BinaryField, a: u8) ValidateError!u8 {
        return try self.validate(a);
    }

    pub fn sub(self: BinaryField, a: u8, b: u8) ValidateError!u8 {
        const neg_b = try self.neg(b);
        return try self.add(a, neg_b);
    }

    fn countBits(num: u16) u5 {
        var v = num;
        var c: u5 = 0;
        while (v != 0) {
            v >>= 1;
            c += 1;
        }
        return c;
    }

    pub fn mul(self: BinaryField, a: u8, b: u8) ValidateError!u8 {
        if (self.exponent() == 1) {
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
        while (result >= self.order()) {
            // count how many binary digits result has
            var j = countBits(result);
            j -= self.exponent() + 1;
            result ^= @as(u16, self.divisor()) << @intCast(j);
        }
        return self.validate(@intCast(result)) catch unreachable;
    }

    pub fn invert(self: BinaryField, a: u8) OpError!u8 {
        if (try self.validate(a) == 0) {
            return error.NoInverse;
        }
        for (0..self.order()) |b| {
            if (try self.mul(a, @intCast(b)) == 1) {
                return self.validate(@intCast(b)) catch unreachable;
            }
        }
        return error.NoInverse;
    }

    pub fn div(self: BinaryField, a: usize, b: usize) OpError!u8 {
        return try self.mul(a, try self.invert(b));
    }

    /// n x n binary matrix representation
    pub fn toMatrix(self: BinaryField, allocator: std.mem.Allocator, a: u8) (std.mem.Allocator.Error || ValidateError)!Matrix {
        var mat = try Matrix.init(allocator, self.matrixNumRows(), self.matrixNumCols());
        errdefer mat.deinit(allocator);
        try self.intoMatrix(&mat, a);
        return mat;
    }

    pub fn intoMatrix(self: BinaryField, dst: *Matrix, a: u8) ValidateError!void {
        assert(self.matrixNumRows() == self.matrixNumCols());

        assert(self.matrixNumRows() == dst.numRows());
        assert(self.matrixNumCols() == dst.numCols());
        const segment = self.matrixNumRows();

        @memset(dst.getDataSlice(), 0);

        var basis: u8 = 1;
        for (0..segment) |col| {
            const p = try self.mul(a, basis);
            basis <<= 1;
            setMatrixCol(dst, col, p);
        }
    }

    pub inline fn cauchyMatrixCellValue(self: BinaryField, params: struct { idx: Matrix.CellIndex, cols: u8 }) OpError!u8 {
        const subtracted = try self.sub(
            params.idx.row + params.cols,
            params.idx.col,
        );
        return try self.invert(subtracted);
    }

    pub inline fn matrixCellCount(self: BinaryField) u16 {
        return Matrix.calcCellCount(self.matrixNumRows(), self.matrixNumCols());
    }
    // zig fmt: off
    pub inline fn matrixNumRows(self: BinaryField) u8 { return self.exponent(); }
    pub inline fn matrixNumCols(self: BinaryField) u8 { return self.exponent(); }
    // zig fmt: on

    fn setMatrixCol(mat: *Matrix, col: usize, value: u8) void {
        for (0..mat.numRows()) |row| {
            const val = (value >> @intCast(row)) & 1;
            mat.set(.{ .row = @intCast(row), .col = @intCast(col) }, val);
        }
    }
};

test "convert to matrix" {
    const bff = try BinaryField.init(3);

    var bfm = try bff.toMatrix(std.testing.allocator, 6);
    defer bfm.deinit(std.testing.allocator);

    try std.testing.expectEqualSlices(u8, bfm.getSlice(0), &[_]u8{ 0, 1, 1 });
    try std.testing.expectEqualSlices(u8, bfm.getSlice(1), &[_]u8{ 1, 1, 0 });
    try std.testing.expectEqualSlices(u8, bfm.getSlice(2), &[_]u8{ 1, 1, 1 });
}
