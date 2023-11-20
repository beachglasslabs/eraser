const eraser = @import("../../pipelines.zig");
const digestBytesToString = eraser.digestBytesToString;

const SensitiveBytes = @import("../../SensitiveBytes.zig");

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util");

const GoogleCloud = @This();
bucket_names: []const []const u8,
auth_token: ?SensitiveBytes.Bounded(max_auth_token_len),

pub const authorization_value_fmt = "Bearer {[auth_token]s}";
pub const object_uri_fmt = "https://storage.googleapis.com/{[bucket]}/{[object]}";

pub const max_auth_token_len = 220;
pub const max_authorization_value_len = std.fmt.count(authorization_value_fmt, .{ .auth_token = "*" ** max_auth_token_len });

pub inline fn objectUriIteratorBufferSize(gc: *const GoogleCloud) usize {
    var result: usize = 0;
    for (gc.bucket_names) |name| result = @max(result, std.fmt.count(object_uri_fmt, .{
        .bucket = util.hardCodeFmt("s", name),
        .object = util.hardCodeFmt("s", &comptime eraser.digestBytesToString("F" ** eraser.chunk.name_len)),
    }));
    return result;
}

pub inline fn authorizationValue(gc: *const GoogleCloud) ?std.BoundedArray(u8, max_authorization_value_len) {
    var result: std.BoundedArray(u8, max_authorization_value_len) = .{};
    const auth_token = if (gc.auth_token) |auth_token| auth_token.getSensitiveSlice() else return null;
    result.writer().print(authorization_value_fmt, .{ .auth_token = auth_token }) catch unreachable;
    return result;
}

/// Asserts `buffer.len == gc.totalObjectUriBytes()`
pub inline fn objectUriIterator(
    gc: *const GoogleCloud,
    object: *const [Sha256.digest_length]u8,
    buffer: []u8,
) ObjectUriIterator {
    assert(gc.objectUriIteratorBufferSize() == buffer.len);
    return .{
        .bucket_names = gc.bucket_names,
        .buffer = buffer,
        .object = object.*,
    };
}

pub const ObjectUriIterator = struct {
    index: usize = 0,
    bucket_names: []const []const u8,
    buffer: []u8,
    object: [Sha256.digest_length]u8,

    /// Each string returned is a unique slice which does not overlap with any previously returned slice.
    pub inline fn next(iter: *ObjectUriIterator) ?[]const u8 {
        if (iter.index == iter.bucket_names.len) return null;
        defer iter.index += 1;
        const bucket = iter.bucket_names[iter.index];

        const object_name_str = digestBytesToString(&iter.object);
        return std.fmt.bufPrint(iter.buffer, object_uri_fmt, .{
            .bucket = util.hardCodeFmt("s", bucket),
            .object = util.hardCodeFmt("s", &object_name_str),
        }) catch unreachable;
    }
};
