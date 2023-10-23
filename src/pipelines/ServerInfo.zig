const pipelines = @import("../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;

const SensitiveBytes = @import("../SensitiveBytes.zig");

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("../util.zig");

const ServerInfo = @This();
shards_required: u7,
google_cloud: ?GoogleCloud = null,
aws: ?Aws = null,

pub const GoogleCloud = @import("ServerInfo/GoogleCloud.zig");
pub const Aws = @import("ServerInfo/Aws.zig");

comptime {
    _ = GoogleCloud;
    _ = Aws;
}

pub inline fn bucketCount(server_info: ServerInfo) usize {
    var result: usize = 0;
    if (server_info.google_cloud) |gcloud| {
        result += gcloud.bucket_names.len;
    }
    if (server_info.aws) |aws| {
        result += aws.buckets.len;
    }
    return result;
}

pub const AuthUpdate = struct {
    gc_auth: ?SensitiveBytes.Fixed(GoogleCloud.auth_token_len),
};
pub inline fn updateAuth(
    server_info: *ServerInfo,
    auth_update: AuthUpdate,
) void {
    if (server_info.google_cloud) |*gc| blk: {
        gc.auth_token = auth_update.gc_auth orelse break :blk;
    }
    if (server_info.aws) |*aws| {
        _ = aws;
        @panic("TODO");
    }
}
