const HeadersUnmanaged = @import("../../HeadersUnmanaged.zig");

const pipelines = @import("../../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;

const SensitiveBytes = @import("../../SensitiveBytes.zig");

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("../../util.zig");

const Aws = @This();
bucket_names: []const []const u8,
access_key: SensitiveBytes,

// std.crypto.auth.hmac.sha2.HmacSha256;

pub const authorization_value_fmt =
    "AWS4-HMAC-SHA256 " ++
    "Credential={[access_key]}/{[date]}/{[region]}/{[service]}/aws4_request, " ++
    "SignedHeaders={[signed_headers]}," ++
    "Signature={[signature]s}" //
;
pub const bucket_object_uri_fmt = "https://{[bucket]s}.s3.amazonaws.com/{[object]s}";

pub fn preAllocated(aws: Aws, allocator: std.mem.Allocator) std.mem.Allocator.Error!PreAllocated {
    var full_size: usize = 0;
    full_size += std.fmt.count("{s}", .{ .auth_token = aws.access_key.getSensitiveSlice() });

    for (aws.bucket_names) |bucket_name| {
        const max_digest_str: []const u8 = comptime &digestBytesToString("\xff" ** Sha256.digest_length);
        full_size += std.fmt.count(bucket_object_uri_fmt, .{
            .bucket = bucket_name,
            .object = max_digest_str,
        });
    }

    const headers_buf = try allocator.alloc(u8, full_size);
    errdefer allocator.free(headers_buf);

    const authorization_value = std.fmt.bufPrint(headers_buf, "{s}", .{ .auth_token = aws.access_key.getSensitiveSlice() }) catch unreachable;
    const bucket_uris_buf = headers_buf[authorization_value.len..];

    var headers: HeadersUnmanaged = .{};
    errdefer headers.deinit(allocator);
    headers.owned = false;

    try headers.append(allocator, "Authorization", authorization_value);
    try headers.append(allocator, "Transfer-Encoding", "chunked");

    return .{
        .bucket_uris_buf = bucket_uris_buf,
        .headers_buf = headers_buf,
        .headers = headers,
    };
}

pub const PreAllocated = struct {
    bucket_uris_buf: []u8,
    headers_buf: []u8,
    headers: HeadersUnmanaged,

    pub fn deinit(pre_allocated: PreAllocated, allocator: std.mem.Allocator) void {
        allocator.free(pre_allocated.headers_buf);

        std.debug.assert(!pre_allocated.headers.owned);
        var copy = pre_allocated.headers;
        copy.deinit(allocator);
    }

    /// The strings obtained from the returned iterator are valid until the next call to this function.
    pub fn bucketObjectUriIterator(self: PreAllocated, gc: Aws, object: *const [Sha256.digest_length]u8) BucketObjectUriIterator {
        return .{
            .bucket_names = gc.bucket_names,
            .bytes = .{ .buffer = self.bucket_uris_buf },
            .object = object,
        };
    }

    pub const BucketObjectUriIterator = struct {
        index: usize = 0,
        bucket_names: []const []const u8,
        bytes: util.BoundedBufferArray(u8),
        object: *const [Sha256.digest_length]u8,

        /// Each string returned is a unique slice which does not overlap with any previously returned slice.
        pub fn next(iter: *BucketObjectUriIterator) ?[]const u8 {
            if (iter.index == iter.bucket_names.len) return null;
            const bucket = iter.bucket_names[iter.index];
            iter.index += 1;

            const start = iter.bytes.len;
            iter.bytes.writer().print(bucket_object_uri_fmt, .{
                .bucket = bucket,
                .object = &digestBytesToString(iter.object),
            }) catch |err| switch (err) {
                error.Overflow => unreachable,
            };
            const end = iter.bytes.len;
            return iter.bytes.slice()[start..end];
        }
    };
};
