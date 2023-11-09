//! Struct to represent a slice of bytes containing sensitive information
//! which should be formatted and inspected with great care.
const std = @import("std");

const SensitiveBytes = @This();
length: usize,
/// using a multi-ptr of this inline enum avoids any introspecting code from easily treating this as a string
// zig fmt: off
pointer: [*]const enum(u8) { _,
    pub fn format(_: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, _: anytype) !void { @compileError("Not printable"); }
},
// zig fmt: on

pub inline fn init(slice: []const u8) SensitiveBytes {
    return .{ .pointer = @ptrCast(slice.ptr), .length = slice.len };
}

pub inline fn getSensitiveSlice(self: SensitiveBytes) []const u8 {
    return @ptrCast(self.pointer[0..self.length]);
}

pub inline fn toBoundedLen(self: SensitiveBytes, comptime max_len: comptime_int) ?Bounded(max_len) {
    return Bounded(max_len).init(self.getSensitiveSlice());
}

pub inline fn toFixedLen(self: SensitiveBytes, comptime length: comptime_int) ?Fixed(length) {
    return Fixed(length).init(self.getSensitiveSlice());
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

pub fn Bounded(comptime max_len: comptime_int) type {
    const SensChar = enum(u8) {
        _,

        pub fn format(_: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, _: anytype) !void {
            @compileError("Not printable");
        }
    };
    return struct {
        sensitive_buffer: [max_len]SensChar,
        length: std.math.IntFittingRange(0, max_len),
        const Self = @This();

        pub inline fn init(slice: []const u8) ?Self {
            if (slice.len > max_len) return null;
            var result: Self = .{
                .sensitive_buffer = undefined,
                .length = @intCast(slice.len),
            };
            @memcpy(result.sensitive_buffer[0..slice.len], @as([]const SensChar, @ptrCast(slice)));
            return result;
        }

        pub inline fn toVarLen(bounded: *const Self) SensitiveBytes {
            return SensitiveBytes.init(bounded.getSensitiveSlice());
        }

        pub inline fn getSensitiveSlice(bounded: *const Self) []const u8 {
            return std.mem.asBytes(&bounded.sensitive_buffer)[0..bounded.length];
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

pub fn Fixed(comptime length: comptime_int) type {
    const SensChar = enum(u8) {
        _,

        pub fn format(_: @This(), comptime _: []const u8, _: std.fmt.FormatOptions, _: anytype) !void {
            @compileError("Not printable");
        }
    };

    return struct {
        sensitive_buffer: [length]SensChar,
        const Self = @This();

        pub inline fn init(slice: []const u8) ?Self {
            if (slice.len != length) return null;
            return .{ .sensitive_buffer = @bitCast(slice[0..length].*) };
        }

        pub inline fn toVarLen(fixed: *const Self) SensitiveBytes {
            return SensitiveBytes.init(fixed.getSensitiveSlice());
        }

        pub inline fn getSensitiveSlice(fixed: *const Self) *const [length]u8 {
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
