const std = @import("std");

pub const DataOrder = @import("matrix.zig").DataOrder;
pub const Matrix = @import("matrix.zig").Matrix;
pub const BinaryFiniteField = @import("finite_field.zig").BinaryFiniteField;
pub const BinaryFieldMatrix = @import("field_matrix.zig").BinaryFieldMatrix;
pub const ErasureCoder = @import("erasure.zig").ErasureCoder;

test {
    _ = @import("matrix.zig");
    _ = @import("finite_field.zig");
    _ = @import("field_matrix.zig");
    _ = @import("erasure.zig");
}
