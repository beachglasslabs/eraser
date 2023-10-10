const pipelines = @import("../../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;

const SensitiveBytes = @import("../../SensitiveBytes.zig");

const std = @import("std");
const assert = std.debug.assert;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("../../util.zig");

const Aws = @This();
bucket_names: []const []const u8,
access_key: SensitiveBytes,

pub const bucket_object_uri_fmt = "https://s3.amazonaws.com/{[bucket]}/{[object]}";

pub inline fn signatureCalculator(
    aws: *const Aws,
    params: struct {
        timestamp: TimestampIso8601,
        scope: Scope,
    },
) SignatureCalculator {
    _ = aws;
    var initial_hasher = Sha256.init(.{});
    initial_hasher.update("AWS4-HMAC-SHA256" ++ "\n");
    initial_hasher.update(&params.timestamp.asBytes().* ++ "\n".*);
    initial_hasher.update();
    return .{ .start = .{
        .hasher = initial_hasher,
    } };
}

pub const SignatureCalculator = union(enum) {
    start: struct {
        hasher: Sha256,
    },
};

pub const Scope = struct {
    access_key_id: ["AKIAIOSFODNN7EXAMPLE".len]u8,
};

pub const TimestampIso8601 = extern struct {
    year: [4]u8,
    month: [2]u8,
    day: [2]u8,
    T: enum(u8) { T = 'T' } = .T,
    hour: [2]u8,
    minute: [2]u8,
    second: [2]u8,
    Z: enum(u8) { Z = 'Z' } = .Z,

    inline fn toBytes(self: *const TimestampIso8601) [@sizeOf(TimestampIso8601)]u8 {
        return self.asBytes().*;
    }
    inline fn asBytes(self: anytype) T: {
        const S = @TypeOf(self);
        const pointer = @typeInfo(S).Pointer;
        assert(pointer.child == TimestampIso8601);
        assert(pointer.size == .One);
        var new_ptr = pointer;
        new_ptr.child = [@sizeOf(TimestampIso8601)]u8;
        break :T @Type(.{ .Pointer = new_ptr });
    } {
        return std.mem.asBytes(self);
    }
};

test TimestampIso8601 {
    try std.testing.expectEqualStrings("2013" ++ "0124" ++ "T" ++ "224915" ++ "Z", &TimestampIso8601.toBytes(&.{
        .year = "2013".*,
        .month = "01".*,
        .day = "24".*,
        .hour = "22".*,
        .minute = "49".*,
        .second = "15".*,
    }));
    try std.testing.expectEqualStrings("0000" ++ "1203" ++ "T" ++ "235959" ++ "Z", &TimestampIso8601.toBytes(&.{
        .year = "0000".*,
        .month = "12".*,
        .day = "03".*,
        .hour = "23".*,
        .minute = "59".*,
        .second = "59".*,
    }));
}
