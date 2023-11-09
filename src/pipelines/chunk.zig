const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const util = @import("util");
const pipelines = @import("../pipelines.zig");
const digestBytesToString = pipelines.digestBytesToString;
const digestStringToBytes = pipelines.digestStringToBytes;

const chunk = @This();

/// Size of the entire chunk, header and data together.
pub const total_size: comptime_int = Header.size + data_size;

/// Size of the data after the header.
pub const data_size: comptime_int = 15 * bytes_per_megabyte;

const bytes_per_megabyte = 1_000_000;

pub const Count = std.math.IntFittingRange(1, std.math.divCeil(u64, std.math.maxInt(u64), chunk.data_size) catch unreachable);

/// The number of chunks required to represent a file of size `file_size`.
pub inline fn countForFileSize(file_size: u64) Count {
    return @intCast(std.math.divCeil(u64, file_size, chunk.data_size) catch unreachable);
}

/// The starting offset in bytes of the chunk of index `chunk_idx`.
/// The first chunk is at the start offset 0.
pub inline fn startOffset(chunk_idx: Count) u64 {
    return @as(u64, chunk_idx) * data_size;
}

pub const name_len = Sha256.digest_length;

pub const Header = struct {
    version: Version = Version.latest,
    /// Represents the SHA of the current chunk's unencrypted data.
    current_chunk_digest: [Sha256.digest_length]u8,
    /// Represents the SHA digest of the entire file. If this header does not represent
    /// the first chunk, this field should be zeroed out & ignored.
    full_file_digest: [Sha256.digest_length]u8,
    /// If there is no subsequent chunk, this field should be zeroed out and ignored.
    next: ChunkRef,

    pub const size =
        Version.size +
        Sha256.digest_length +
        Sha256.digest_length +
        ChunkRef.size //
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
        comptime var ils = util.InlineSlicer.init(u8, bytes.len);
        defer ils.finish();

        // read version
        const version: Version = Version.fromBytes(ils.next(bytes, Version.size).*);
        switch (version.order(Version.latest)) {
            .gt => return error.UnrecognizedHeaderVersion,
            .lt => @panic("This should not yet be possible"),
            .eq => {},
        }

        return .{
            .version = version,
            .current_chunk_digest = ils.next(bytes, Sha256.digest_length).*, // read the SHA of the current chunk's unencrypted data
            .full_file_digest = ils.next(bytes, Sha256.digest_length).*, // read the SHA of the entire unencrypted file, if present
            .next = ChunkRef.fromBytes(ils.next(bytes, ChunkRef.size)), // read the info about the next chunk, if present
        };
    }
};

pub const ChunkRef = struct {
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

    pub const zero_init: ChunkRef = .{
        .chunk_blob_digest = .{0} ** Sha256.digest_length,
        .encryption = Encryption.zero_init,
    };

    pub inline fn toBytes(next: *const ChunkRef) [ChunkRef.size]u8 {
        return [0]u8{} ++
            next.chunk_blob_digest ++
            next.encryption.toBytes();
    }

    pub inline fn fromBytes(bytes: *const [ChunkRef.size]u8) ChunkRef {
        comptime var ils = util.InlineSlicer.init(u8, bytes.len);
        defer ils.finish();
        return .{
            .chunk_blob_digest = ils.next(bytes, Sha256.digest_length).*,
            .encryption = Encryption.fromBytes(ils.nextRemaining(bytes)),
        };
    }
};

pub const Version = extern struct {
    major: u16,
    minor: u16,
    patch: u16,
    const latest: Version = .{ .major = 0, .minor = 0, .patch = 0 };

    pub const size = @sizeOf(Version);
    comptime {
        assert(size == @sizeOf([3]u16));
    }

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

    pub const zero_init: Encryption = .{
        .tag = .{0} ** Aes256Gcm.tag_length,
        .npub = .{0} ** Aes256Gcm.nonce_length,
        .key = .{0} ** Aes256Gcm.key_length,
    };

    pub inline fn toBytes(enc: *const Encryption) [Encryption.size]u8 {
        return [0]u8{} ++
            enc.tag ++
            enc.npub ++
            enc.key;
    }

    pub inline fn fromBytes(bytes: *const [Encryption.size]u8) Encryption {
        comptime var ils = util.InlineSlicer.init(u8, bytes.len);
        defer ils.finish();
        return .{
            .tag = ils.next(bytes, Aes256Gcm.tag_length).*,
            .npub = ils.next(bytes, Aes256Gcm.nonce_length).*,
            .key = ils.next(bytes, Aes256Gcm.key_length).*,
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

pub inline fn encryptedChunkIterator(
    /// `std.io.Reader(...)`
    reader: anytype,
    /// Should be the seeker for `reader`.
    /// `std.io.SeekableStream(...)`
    seeker: anytype,
    params: struct {
        full_file_digest: [Sha256.digest_length]u8,
        /// Number of expected chunks
        chunk_count: chunk.Count,
        /// decrypted_chunk_buffer = &buffer[0]
        /// encrypted_chunk_buffer = &buffer[1]
        buffers: *[2][Header.size + chunk.data_size]u8,
    },
) EncryptedChunkIterator(@TypeOf(reader), @TypeOf(seeker)) {
    return .{
        .reader = reader,
        .seeker = seeker,
        .full_file_digest = params.full_file_digest,
        .buffers = params.buffers,
        .chunk_count = params.chunk_count,
        .chunk_idx = params.chunk_count,
        .next_chunk_info = chunk.ChunkRef.zero_init,
    };
}

pub fn EncryptedChunkIterator(
    /// `std.io.Reader(...)`
    comptime Reader: type,
    /// `std.io.SeekableStream(...)`
    comptime SeekableStream: type,
) type {
    return struct {
        reader: Reader,
        seeker: SeekableStream,
        full_file_digest: [Sha256.digest_length]u8,
        buffers: *[2][Header.size + chunk.data_size]u8,
        chunk_count: chunk.Count,
        chunk_idx: chunk.Count,
        next_chunk_info: chunk.ChunkRef,
        const Self = @This();

        pub const NextResult = struct {
            /// The name of the encrypted chunk
            name: *const [chunk.name_len]u8,
            /// The encrypted data
            encrypted: []const u8,
        };

        /// The returned pointers are only valid up until the next call to `self.next(...)`
        pub fn next(
            self: *Self,
            params: struct {
                npub: *const [Aes256Gcm.nonce_length]u8,
                key: *const [Aes256Gcm.key_length]u8,
            },
        ) (Reader.Error || SeekableStream.SeekError)!?NextResult {
            const decrypted_chunk_buffer: *[Header.size + chunk.data_size]u8 = &self.buffers[0];
            const encrypted_chunk_buffer: *[Header.size + chunk.data_size]u8 = &self.buffers[1];

            if (self.chunk_idx == 0) return null;
            self.chunk_idx -= 1;
            const chunk_idx = self.chunk_idx;
            const offset = startOffset(self.chunk_idx);

            const decrypted_chunk_blob = blk: {
                const header_buffer: *[chunk.Header.size]u8 = decrypted_chunk_buffer[0..chunk.Header.size];
                const data_buffer: *[chunk.data_size]u8 = decrypted_chunk_buffer[header_buffer.len..];
                self.seeker.seekTo(offset) catch |err| switch (err) {
                    inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                };
                const data_bytes_len = try self.reader.readAll(data_buffer);
                const chunk_data = data_buffer[0..data_bytes_len];

                var current_chunk_header: chunk.Header = .{
                    .current_chunk_digest = undefined,
                    .full_file_digest = if (chunk_idx == 0) self.full_file_digest else .{0} ** Sha256.digest_length,
                    .next = self.next_chunk_info,
                };
                Sha256.hash(chunk_data, &current_chunk_header.current_chunk_digest, .{});
                header_buffer.* = current_chunk_header.toBytes();
                break :blk decrypted_chunk_buffer[0 .. chunk.Header.size + data_bytes_len];
            };

            const associated_data = "";
            var auth_tag: [Aes256Gcm.tag_length]u8 = undefined;
            const npub = params.npub;
            const key = params.key;
            Aes256Gcm.encrypt(
                encrypted_chunk_buffer[0..decrypted_chunk_blob.len],
                &auth_tag,
                decrypted_chunk_blob,
                associated_data,
                npub.*,
                key.*,
            );
            const encrypted_chunk_blob: []const u8 = encrypted_chunk_buffer[0..decrypted_chunk_blob.len];

            self.next_chunk_info = .{
                .chunk_blob_digest = undefined,
                .encryption = .{
                    .tag = auth_tag,
                    .npub = npub.*,
                    .key = key.*,
                },
            };
            Sha256.hash(encrypted_chunk_blob, &self.next_chunk_info.chunk_blob_digest, .{});

            return .{
                .name = &self.next_chunk_info.chunk_blob_digest,
                .encrypted = encrypted_chunk_blob,
            };
        }

        pub inline fn storedFile(self: *const Self) pipelines.StoredFile {
            assert(self.chunk_idx == 0);
            return .{
                .encryption = self.next_chunk_info.encryption,
                .first_name = self.next_chunk_info.chunk_blob_digest,
                .chunk_count = self.chunk_count,
            };
        }
    };
}
