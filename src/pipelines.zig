const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("util.zig");

pub const erasure = @import("erasure.zig");
pub const SensitiveBytes = @import("SensitiveBytes.zig");

pub const ServerInfo = @import("pipelines/ServerInfo.zig");
pub const PipelineInitValues = @import("pipelines/PipelineInitValues.zig");

const upload = @import("pipelines/upload.zig");
pub const UploadCtx = upload.Ctx;
pub const UploadPipeLine = upload.PipeLine;

const download = @import("pipelines/download.zig");
pub const DownloadCtx = download.Ctx;
pub const DownloadPipeLine = download.PipeLine;

pub fn digestBytesToString(bytes: *const [Sha256.digest_length]u8) [Sha256.digest_length * 2]u8 {
    return std.fmt.bytesToHex(bytes.*, .lower);
}
pub const DigestStringToBytesError = error{ InvalidDigestLength, InvalidCharacter };
pub fn digestStringToBytes(str: *const [Sha256.digest_length * 2]u8) DigestStringToBytesError![Sha256.digest_length]u8 {
    var digest = [_]u8{0} ** Sha256.digest_length;
    const digest_slice = std.fmt.hexToBytes(&digest, str) catch |err| switch (err) {
        error.InvalidLength => unreachable,
        error.NoSpaceLeft => unreachable,
        error.InvalidCharacter => |e| return e,
    };
    assert(digest.len == digest_slice.len);
    return digest;
}
