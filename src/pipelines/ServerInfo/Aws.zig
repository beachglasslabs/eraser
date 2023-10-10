const HeadersUnmanaged = @import("../../HeadersUnmanaged.zig");

const pipelines = @import("../../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;

const SensitiveBytes = @import("../../SensitiveBytes.zig");

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;

const util = @import("../../util.zig");

const Aws = @This();
bucket_names: []const []const u8,
access_key: SensitiveBytes,

pub const authorization_value_fmt =
    "AWS4-HMAC-SHA256 " ++
    "Credential={[access_key]}/{[date]}/{[region]}/{[service]}/aws4_request, " ++
    "SignedHeaders={[signed_headers]}," ++
    "Signature={[signature]}" //
;
pub const bucket_object_uri_fmt = "https://s3.amazonaws.com/{[bucket]}/{[object]}";
