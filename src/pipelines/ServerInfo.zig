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

pub inline fn bucketCount(server_info: ServerInfo) usize {
    var result: usize = 0;
    if (server_info.google_cloud) |gcloud| {
        result += gcloud.bucket_names.len;
    }
    return result;
}
