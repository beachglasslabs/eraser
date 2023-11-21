const pipelines = @import("../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;

const SensitiveBytes = @import("../SensitiveBytes.zig");

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util");

const Providers = @This();
shards_required: u7,
shard_buckets: []const Bucket,
google_cloud: GoogleCloud,
aws: Aws,

pub const GoogleCloud = @import("Providers/GoogleCloud.zig");
pub const Aws = @import("Providers/Aws.zig");

pub const Bucket = union(enum) {
    gcloud: GoogleCloud.Bucket,
    aws: Aws.Bucket,
};

comptime {
    _ = GoogleCloud;
    _ = Aws;
}
