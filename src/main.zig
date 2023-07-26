const std = @import("std");
const testing = std.testing;
const bfm = @import("bf_matrix.zig");

test "simd matrix" {
    const fm3 = try bfm.BinaryFiniteMatrix(3).init(testing.allocator);
    const c6 = try fm3.simdColMat(6);
    defer testing.allocator.free(c6);
    try testing.expectEqual(c6[0], @Vector(3, u8){ 0, 1, 1 });
    try testing.expectEqual(c6[1], @Vector(3, u8){ 1, 1, 1 });
    try testing.expectEqual(c6[2], @Vector(3, u8){ 1, 0, 1 });
    const r6 = try fm3.simdRowMat(6);
    defer testing.allocator.free(r6);
    try testing.expectEqual(r6[0], @Vector(3, u8){ 0, 1, 1 });
    try testing.expectEqual(r6[1], @Vector(3, u8){ 1, 1, 0 });
    try testing.expectEqual(r6[2], @Vector(3, u8){ 1, 1, 1 });
}
