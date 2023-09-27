const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const chunk = @import("pipelines/chunk.zig");
pub const erasure = @import("erasure.zig");
pub const erasure2 = @import("erasure2.zig");
pub const SensitiveBytes = @import("SensitiveBytes.zig");
pub const ServerInfo = @import("pipelines/ServerInfo.zig");

const upload = @import("pipelines/upload.zig");
pub const uploadPipeline = upload.pipeLine;
pub const UploadPipeLine = upload.PipeLine;

const download = @import("pipelines/download.zig");
pub const DownloadPipeLine = download.PipeLine;

comptime {
    _ = chunk;
    _ = erasure;
    _ = erasure2;
    _ = SensitiveBytes;
    _ = ServerInfo;
    _ = upload;
    _ = download;
}

pub const StoredFile = struct {
    encryption: chunk.Encryption,
    first_name: [Sha256.digest_length]u8,
    chunk_count: chunk.Count,
};

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

pub inline fn threadSafeRng(inner: std.rand.Random) ThreadSafeRandom {
    return .{ .inner = inner };
}

pub const ThreadSafeRandom = struct {
    mtx: std.Thread.Mutex = .{},
    inner: std.rand.Random,

    pub inline fn random(tsr: *ThreadSafeRandom) std.rand.Random {
        return std.rand.Random.init(tsr, ThreadSafeRandom.fillImpl);
    }

    fn fillImpl(tsr: *ThreadSafeRandom, buf: []u8) void {
        tsr.mtx.lock();
        defer tsr.mtx.unlock();
        tsr.inner.bytes(buf);
    }
};
