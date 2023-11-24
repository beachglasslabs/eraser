const std = @import("std");
const util = @import("util");

const Providers = @This();
shards_required: u7,
shard_buckets: []const Bucket,
auth: Auth,

pub const GoogleCloud = @import("Providers/GoogleCloud.zig");
pub const Aws = @import("Providers/Aws.zig");

pub const Bucket = union(enum) {
    gcloud: GoogleCloud.Bucket,
    aws: Aws.Bucket,
};
pub const Auth = struct {
    gcloud: *GoogleCloud,
    aws: *Aws,
};

comptime {
    _ = GoogleCloud;
    _ = Aws;
}
