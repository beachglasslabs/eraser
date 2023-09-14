const pipelines = @import("../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;

const SensitiveBytes = @import("../SensitiveBytes.zig");

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("../util.zig");

const ServerInfo = @This();
shard_size: u7,
google_cloud: ?GoogleCloud = null,

pub const GoogleCloud = struct {
    auth_token: SensitiveBytes,
    bucket_names: []const []const u8,

    const authorization_value_fmt = "Bearer {[auth_token]s}";
    const bucket_object_uri_fmt = "https://storage.googleapis.com/{[bucket]s}/{[object]s}";

    pub fn preAllocated(gc: GoogleCloud, allocator: std.mem.Allocator) std.mem.Allocator.Error!PreAllocated {
        var full_size: usize = 0;
        full_size += std.fmt.count(authorization_value_fmt, .{ .auth_token = gc.auth_token.getSensitiveSlice() });

        for (gc.bucket_names) |bucket_name| {
            const max_digest_str: []const u8 = comptime &digestBytesToString("\xff" ** Sha256.digest_length);
            full_size += std.fmt.count(bucket_object_uri_fmt, .{
                .bucket = bucket_name,
                .object = max_digest_str,
            });
        }

        const full_buf_alloc = try allocator.alloc(u8, full_size);
        errdefer allocator.free(full_buf_alloc);

        const authorization_value = std.fmt.bufPrint(full_buf_alloc, authorization_value_fmt, .{ .auth_token = gc.auth_token.getSensitiveSlice() }) catch unreachable;
        const bucket_uris_buf = full_buf_alloc[authorization_value.len..];

        var headers = std.http.Headers.init(allocator);
        errdefer headers.deinit();
        headers.owned = false;

        try headers.append("Authorization", authorization_value);
        try headers.append("Transfer-Encoding", "chunked");

        return .{
            .full_buf_alloc = full_buf_alloc,
            .authorization_value = authorization_value,
            .bucket_uris_buf = bucket_uris_buf,
            .headers = headers,
        };
    }

    pub const PreAllocated = struct {
        full_buf_alloc: []u8,
        authorization_value: []const u8,
        bucket_uris_buf: []u8,
        headers: std.http.Headers,

        pub fn deinit(pre_allocated: PreAllocated, allocator: std.mem.Allocator) void {
            allocator.free(pre_allocated.full_buf_alloc);

            var headers_copy = pre_allocated.headers;
            headers_copy.allocator = allocator;
            headers_copy.deinit();
        }

        /// The strings obtained from the returned iterator are valid until the next call to this function.
        pub fn bucketObjectUriIterator(self: PreAllocated, gc: GoogleCloud, object: *const [Sha256.digest_length]u8) BucketObjectUriIterator {
            return .{
                .bucket_names = gc.bucket_names,
                .bytes = .{ .buffer = self.bucket_uris_buf },
                .object = object,
            };
        }

        const BucketObjectUriIterator = struct {
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
};

pub inline fn bucketCount(server_info: ServerInfo) usize {
    var result: usize = 0;
    if (server_info.google_cloud) |gcloud| {
        result += gcloud.bucket_names.len;
    }
    return result;
}
