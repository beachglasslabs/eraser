const pipelines = @import("../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;

const SensitiveBytes = @import("../SensitiveBytes.zig");

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util");

const Providers = @This();
shards_required: u7,
google_cloud: ?GoogleCloud = null,
aws: ?Aws = null,

pub const GoogleCloud = @import("Providers/GoogleCloud.zig");
pub const Aws = @import("Providers/Aws.zig");

comptime {
    _ = GoogleCloud;
    _ = Aws;
}

pub inline fn bucketCount(server_info: Providers) usize {
    var result: usize = 0;
    if (server_info.google_cloud) |gcloud| {
        result += gcloud.bucket_names.len;
    }
    if (server_info.aws) |aws| {
        result += aws.buckets.len;
    }
    return result;
}
