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

pub inline fn toFixedLen(self: SensitiveBytes, comptime len: comptime_int) ?Fixed(len) {
    if (self.length != len) return null;
    return .{ .sensitive_buffer = @bitCast(self.getSensitiveSlice()[0..len].*) };
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

pub fn Fixed(comptime len: comptime_int) type {
    const SensChar = enum(u8) {
        _,

        pub fn format(_: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, _: anytype) !void {
            @compileError("Not printable");
        }
    };

    return struct {
        sensitive_buffer: [len]SensChar,
        const Self = @This();

        pub inline fn init(slice: []const u8) ?Self {
            return SensitiveBytes.init(slice).toFixedLen(len);
        }

        pub inline fn toVarLen(fixed: *const Self) SensitiveBytes {
            return SensitiveBytes.init(fixed.getSensitiveSlice());
        }

        pub inline fn getSensitiveSlice(fixed: *const Self) *const [len]u8 {
            return std.mem.asBytes(&fixed.sensitive_buffer);
        }

        pub fn format(
            self: *const Self,
            comptime fmt_str: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            return self.toVarLen().format(fmt_str, options, writer);
        }
    };
}
