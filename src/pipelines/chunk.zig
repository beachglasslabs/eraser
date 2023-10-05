const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const util = @import("../util.zig");
const pipelines = @import("../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;
const digestStringToBytes = pipelines.digestStringToBytes;

const chunk = @This();

pub const size: comptime_int = 15 * bytes_per_megabyte;
const bytes_per_megabyte = 1_000_000;

pub const Count = std.math.IntFittingRange(1, std.math.divCeil(u64, std.math.maxInt(u64), chunk.size) catch unreachable);
pub inline fn countForFileSize(file_size: u64) Count {
    return @intCast(std.math.divCeil(u64, file_size, chunk.size) catch unreachable);
}
pub inline fn startOffset(chunk_idx: Count) u64 {
    return (@as(u64, chunk_idx) * size);
}

pub const Header = struct {
    version: Version = Version.latest,
    /// Represents the SHA of the current chunk's unencrypted data.
    current_chunk_digest: [Sha256.digest_length]u8,
    /// Represents the SHA digest of the entire file. If this header does not represent
    /// the first chunk, this field should be zeroed out & ignored.
    full_file_digest: [Sha256.digest_length]u8,
    /// If there is no subsequent chunk, this field should be zeroed out and ignored.
    next: NextInfo,

    pub const size =
        Version.size +
        Sha256.digest_length +
        Sha256.digest_length +
        NextInfo.size //
    ;

    pub inline fn toBytes(header: *const Header) [Header.size]u8 {
        return [0]u8{} ++
            header.version.toBytes() ++
            header.current_chunk_digest ++
            header.full_file_digest ++
            header.next.toBytes() //
        ;
    }

    pub const ReadHeaderError = error{UnrecognizedHeaderVersion};
    pub inline fn fromBytes(bytes: *const [Header.size]u8) ReadHeaderError!Header {
        comptime var cursor = 0;

        // read version
        const version: Version = blk: {
            defer cursor += Version.size;
            break :blk Version.fromBytes(bytes[cursor..][0..Version.size].*);
        };
        switch (version.order(Version.latest)) {
            .gt => return error.UnrecognizedHeaderVersion,
            .lt => @panic("This should not yet be possible"),
            .eq => {},
        }

        // read the SHA of the current chunk's unencrypted data
        const current_chunk_digest: *const [Sha256.digest_length]u8 = bytes[cursor..][0..Sha256.digest_length];
        cursor += current_chunk_digest.len;

        // read the SHA of the entire unencrypted file, if present
        const full_file_digest: *const [Sha256.digest_length]u8 = bytes[cursor..][0..Sha256.digest_length];
        cursor += full_file_digest.len;

        // read the info about the next chunk, if present
        const next: Header.NextInfo = Header.NextInfo.fromBytes(bytes[cursor..][0..Header.NextInfo.size]);
        cursor += Header.NextInfo.size;

        comptime assert(cursor == bytes.len);
        return .{
            .version = version,
            .current_chunk_digest = current_chunk_digest.*,
            .full_file_digest = full_file_digest.*,
            .next = next,
        };
    }

    pub const NextInfo = struct {
        /// Represents the SHA of the blob comprised of the next chunk's unencrypted header
        /// and data.
        /// If there is no subsequent chunk, this field should be zeroed out and ignored.
        chunk_blob_digest: [Sha256.digest_length]u8,
        /// Represents the encryption information of the next chunk.
        /// If there is no subsequent chunk, this field should be zeroed out and ignored.
        encryption: Encryption,

        pub const size =
            Sha256.digest_length +
            Encryption.size //
        ;

        pub inline fn toBytes(next: *const NextInfo) [NextInfo.size]u8 {
            return [0]u8{} ++
                next.chunk_blob_digest ++
                next.encryption.toBytes();
        }

        pub inline fn fromBytes(bytes: *const [NextInfo.size]u8) NextInfo {
            return .{
                .chunk_blob_digest = bytes[0..Sha256.digest_length].*,
                .encryption = Encryption.fromBytes(bytes[Sha256.digest_length..]),
            };
        }
    };
};

pub const Version = extern struct {
    major: u16,
    minor: u16,
    patch: u16,

    comptime {
        assert(@sizeOf(Version) == @sizeOf([3]u16));
    }

    const latest: Version = .{ .major = 0, .minor = 0, .patch = 0 };
    pub const size = @sizeOf(Version);

    pub fn order(self: Version, other: Version) std.math.Order {
        const major = std.math.order(self.major, other.major);
        const minor = std.math.order(self.minor, other.minor);
        const patch = std.math.order(self.patch, other.patch);

        return switch (major) {
            .lt => .lt,
            .gt => .gt,
            .eq => switch (minor) {
                .lt => .lt,
                .gt => .gt,
                .eq => switch (patch) {
                    .lt => .lt,
                    .gt => .gt,
                    .eq => .eq,
                },
            },
        };
    }

    pub inline fn toBytes(chv: Version) [Version.size]u8 {
        return @bitCast(Version{
            .major = std.mem.nativeToLittle(u16, chv.major),
            .minor = std.mem.nativeToLittle(u16, chv.minor),
            .patch = std.mem.nativeToLittle(u16, chv.patch),
        });
    }
    pub inline fn fromBytes(bytes: [Version.size]u8) Version {
        const le: Version = @bitCast(bytes);
        return .{
            .major = std.mem.littleToNative(u16, le.major),
            .minor = std.mem.littleToNative(u16, le.minor),
            .patch = std.mem.littleToNative(u16, le.patch),
        };
    }
};

pub const Encryption = struct {
    tag: [Aes256Gcm.tag_length]u8,
    npub: [Aes256Gcm.nonce_length]u8,
    key: [Aes256Gcm.key_length]u8,

    pub const size =
        Aes256Gcm.tag_length +
        Aes256Gcm.nonce_length +
        Aes256Gcm.key_length //
    ;

    pub inline fn toBytes(enc: *const Encryption) [Encryption.size]u8 {
        return [0]u8{} ++
            enc.tag ++
            enc.npub ++
            enc.key;
    }

    pub inline fn fromBytes(bytes: *const [Encryption.size]u8) Encryption {
        comptime var cursor = 0;
        defer comptime assert(cursor == bytes.len);

        const tag = bytes[cursor..][0..Aes256Gcm.tag_length];
        cursor += tag.len;

        const npub = bytes[cursor..][0..Aes256Gcm.nonce_length];
        cursor += npub.len;

        const key = bytes[cursor..][0..Aes256Gcm.key_length];
        cursor += key.len;

        return .{
            .tag = tag.*,
            .npub = npub.*,
            .key = key.*,
        };
    }
};

test Header {
    try testChunkHeader(.{
        .current_chunk_digest = try comptime digestStringToBytes("Cd" ** Sha256.digest_length),
        .full_file_digest = .{0} ** Sha256.digest_length,
        .next = .{
            .chunk_blob_digest = try comptime digestStringToBytes("aB" ** Sha256.digest_length),
            .encryption = .{
                .tag = .{7} ** Aes256Gcm.tag_length,
                .npub = .{15} ** Aes256Gcm.nonce_length,
                .key = .{32} ** Aes256Gcm.key_length,
            },
        },
    });
    try testChunkHeader(.{
        .current_chunk_digest = try comptime digestStringToBytes("cD" ** Sha256.digest_length),
        .full_file_digest = .{0} ** Sha256.digest_length,
        .next = .{
            .chunk_blob_digest = try comptime digestStringToBytes("Ab" ** Sha256.digest_length),
            .encryption = .{
                .tag = .{7} ** Aes256Gcm.tag_length,
                .npub = .{15} ** Aes256Gcm.nonce_length,
                .key = .{32} ** Aes256Gcm.key_length,
            },
        },
    });
    try testChunkHeader(.{
        .current_chunk_digest = try comptime digestStringToBytes("Cd" ** Sha256.digest_length),
        .full_file_digest = .{31} ** Sha256.digest_length,
        .next = .{
            .chunk_blob_digest = try comptime digestStringToBytes("Ab" ** Sha256.digest_length),
            .encryption = .{
                .tag = .{7} ** Aes256Gcm.tag_length,
                .npub = .{15} ** Aes256Gcm.nonce_length,
                .key = .{32} ** Aes256Gcm.key_length,
            },
        },
    });
}

fn testChunkHeader(ch: Header) !void {
    const actual = try Header.fromBytes(&ch.toBytes());
    try std.testing.expectEqual(ch, actual);
}
