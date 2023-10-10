//! Struct to represent a slice of bytes containing sensitive information
//! which should be formatted and inspected with great care.
const std = @import("std");

const SensitiveBytes = @This();
/// using a multi-ptr avoids any introspecting code from easily treating this as a string
pointer: [*]const u8,
length: usize,

pub inline fn init(slice: []const u8) SensitiveBytes {
    return .{ .pointer = slice.ptr, .length = slice.len };
}

pub inline fn getSensitiveSlice(self: SensitiveBytes) []const u8 {
    return self.pointer[0..self.length];
}

pub fn format(
    self: SensitiveBytes,
    comptime fmt_str: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    comptime if (!std.mem.eql(u8, fmt_str, "SENSITIVE"))
        @compileError("Cannot format SensitiveBytes without format specifier being 'SENSITIVE'");
    _ = options;
    try writer.writeByteNTimes('*', @max(1, self.length));
}

test SensitiveBytes {
    try std.testing.expectFmt("******", "{SENSITIVE}", .{SensitiveBytes.init("secret")});
}
