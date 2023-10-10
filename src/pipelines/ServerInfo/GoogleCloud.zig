const HeadersUnmanaged = @import("../../HeadersUnmanaged.zig");

const pipelines = @import("../../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;

const SensitiveBytes = @import("../../SensitiveBytes.zig");

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("../../util.zig");

const GoogleCloud = @This();
auth_token: SensitiveBytes,
bucket_names: []const []const u8,

pub const authorization_value_fmt = "Bearer {[auth_token]s}";
pub const object_uri_fmt = "https://storage.googleapis.com/{[bucket]}/{[object]}";

pub const auth_token_len = 218;
pub const authorization_value_len = std.fmt.count(authorization_value_fmt, .{ .auth_token = "A" ** auth_token_len });

pub inline fn authorizationValue(gc: *const GoogleCloud) [authorization_value_len]u8 {
    var result: [authorization_value_len]u8 = undefined;
    assert(result.len == (std.fmt.bufPrint(&result, authorization_value_fmt, .{
        .auth_token = gc.auth_token.getSensitiveSlice(),
    }) catch unreachable).len);
    return result;
}

pub inline fn totalObjectUrisByteCount(gc: *const GoogleCloud) usize {
    var result: usize = 0;
    for (gc.bucket_names) |name| result += std.fmt.count(object_uri_fmt, .{
        .bucket = util.hardCodeFmt("s", name),
        .object = util.hardCodeFmt("s", &comptime pipelines.digestBytesToString("F" ** Sha256.digest_length)),
    });
    return result;
}

/// Asserts `buffer.len == gc.totalObjectUriBytes()`
pub inline fn objectUriIterator(
    gc: *const GoogleCloud,
    object: *const [Sha256.digest_length]u8,
    buffer: []u8,
) ObjectUriIterator {
    assert(gc.totalObjectUrisByteCount() == buffer.len);
    return .{
        .bucket_names = gc.bucket_names,
        .bytes = .{ .buffer = buffer },
        .object = object.*,
    };
}

pub const ObjectUriIterator = struct {
    index: usize = 0,
    bucket_names: []const []const u8,
    bytes: util.BoundedBufferArray(u8),
    object: [Sha256.digest_length]u8,

    /// Each string returned is a unique slice which does not overlap with any previously returned slice.
    pub inline fn next(iter: *ObjectUriIterator) ?[]const u8 {
        if (iter.index == iter.bucket_names.len) return null;
        const bucket = iter.bucket_names[iter.index];
        iter.index += 1;

        const start = iter.bytes.len;
        iter.bytes.writer().print(object_uri_fmt, .{
            .bucket = util.hardCodeFmt("s", bucket),
            .object = util.hardCodeFmt("s", &digestBytesToString(&iter.object)),
        }) catch |err| switch (err) {
            error.Overflow => unreachable,
        };
        return iter.bytes.slice()[start..];
    }
};

// pub fn preAllocated(gc: GoogleCloud, allocator: std.mem.Allocator) std.mem.Allocator.Error!PreAllocated {
//     var full_size: usize = 0;
//     full_size += authorization_value_len;

//     for (gc.bucket_names) |bucket_name|
//         assert(bucket_name.len <= "ec127.blocktube.net".len);
//     full_size += bucket_object_uri_len;

//     const headers_buf = try allocator.alloc(u8, full_size);
//     errdefer allocator.free(headers_buf);

//     const authorization_value = std.fmt.bufPrint(headers_buf, authorization_value_fmt, .{ .auth_token = gc.auth_token.getSensitiveSlice() }) catch unreachable;
//     const bucket_uris_buf = headers_buf[authorization_value.len..];

//     var headers: HeadersUnmanaged = .{};
//     errdefer headers.deinit(allocator);
//     headers.owned = false;

//     try headers.append(allocator, "Authorization", authorization_value);
//     try headers.append(allocator, "Transfer-Encoding", "chunked");

//     return .{
//         .bucket_uris_buf = bucket_uris_buf,
//         .headers_buf = headers_buf,
//         .headers = headers,
//     };
// }

// pub const PreAllocated = struct {
//     bucket_uris_buf: []u8,
//     headers_buf: []u8,
//     headers: HeadersUnmanaged,

//     pub fn deinit(pre_allocated: PreAllocated, allocator: std.mem.Allocator) void {
//         allocator.free(pre_allocated.headers_buf);

//         std.debug.assert(!pre_allocated.headers.owned);
//         var copy = pre_allocated.headers;
//         copy.deinit(allocator);
//     }

//     /// The strings obtained from the returned iterator are valid until the next call to this function.
//     pub fn bucketObjectUriIterator(self: PreAllocated, gc: GoogleCloud, object: *const [Sha256.digest_length]u8) BucketObjectUriIterator {
//         return .{
//             .bucket_names = gc.bucket_names,
//             .bytes = .{ .buffer = self.bucket_uris_buf },
//             .object = object,
//         };
//     }

//     pub const BucketObjectUriIterator = struct {
//         index: usize = 0,
//         bucket_names: []const []const u8,
//         bytes: util.BoundedBufferArray(u8),
//         object: *const [Sha256.digest_length]u8,

//         /// Each string returned is a unique slice which does not overlap with any previously returned slice.
//         pub fn next(iter: *BucketObjectUriIterator) ?[]const u8 {
//             if (iter.index == iter.bucket_names.len) return null;
//             const bucket = iter.bucket_names[iter.index];
//             iter.index += 1;

//             const start = iter.bytes.len;
//             iter.bytes.writer().print(bucket_object_uri_fmt, .{
//                 .bucket = bucket,
//                 .object = &digestBytesToString(iter.object),
//             }) catch |err| switch (err) {
//                 error.Overflow => unreachable,
//             };
//             const end = iter.bytes.len;
//             return iter.bytes.slice()[start..end];
//         }
//     };
// };
