const eraser = @import("../../pipelines.zig");
const digestBytesToString = eraser.digestBytesToString;

const SensitiveBytes = @import("../../SensitiveBytes.zig");

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util");

const GoogleCloud = @This();
auth_token: ?SensitiveBytes.Bounded(max_auth_token_len),

pub const authorization_value_fmt = "Bearer {[auth_token]s}";
pub const object_uri_fmt = "{[protocol]s}://storage.googleapis.com/{[bucket]}/{[object]}";

pub const max_auth_token_len = 220;
pub const max_authorization_value_len = std.fmt.count(authorization_value_fmt, .{ .auth_token = "*" ** max_auth_token_len });

pub const Bucket = struct {
    name: []const u8,

    pub const WriteUriOptions = struct {
        /// e.g. "http", "https".
        protocol: []const u8,
        /// If set to a non-null, writes this as the sub-object path of the bucket URI.
        object: ?[]const u8,
    };

    pub inline fn writeUriTo(bucket: Bucket, writer: anytype, options: WriteUriOptions) @TypeOf(writer).Error!void {
        try writer.print("{[protocol]s}://storage.googleapis.com/{[bucket]s}", .{
            .protocol = options.protocol,
            .bucket = bucket.name,
        });
        if (options.object) |object| {
            try writer.print("/{s}", .{object});
        }
    }

    pub inline fn fmtUri(bucket: Bucket) FmtUri {
        return .{ .bucket = bucket };
    }

    pub const FmtUri = struct {
        bucket: Bucket,
        options: WriteUriOptions,

        pub fn format(
            self: FmtUri,
            comptime fmt_str: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = options;
            if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, self);
            try self.bucket.writeUriTo(writer, self.options);
        }
    };
};

pub inline fn authorizationValue(gc: *const GoogleCloud) ?std.BoundedArray(u8, max_authorization_value_len) {
    var result: std.BoundedArray(u8, max_authorization_value_len) = .{};
    const auth_token = if (gc.auth_token) |auth_token| auth_token.getSensitiveSlice() else return null;
    result.writer().print(authorization_value_fmt, .{ .auth_token = auth_token }) catch unreachable;
    return result;
}
