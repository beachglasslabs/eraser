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
    version: HeaderVersion = HeaderVersion.latest,
    /// Represents the SHA of the current chunk's unencrypted data.
    current_chunk_digest: [Sha256.digest_length]u8,
    /// Represents the SHA digest of the entire file. If this header does not represent
    /// the first chunk, this field is null.
    full_file_digest: ?[Sha256.digest_length]u8,
    /// If there is no chunk after the one represented by this header, this field is null.
    next: ?NextInfo,

    pub const DataFlags = packed struct(u8) {
        full_file_digest: bool,
        next: bool,
        unused: enum(u6) { unset = 0 } = .unset,
    };

    pub const NextInfo = struct {
        /// Represents the SHA of the blob comprised of the next chunk's header and data.
        chunk_blob_digest: [Sha256.digest_length]u8,
        /// Represents the encryption information of the next chunk.
        encryption: Encryption,

        pub inline fn write(next: *const NextInfo, writer: anytype) @TypeOf(writer).Error!void {
            try writer.writeAll(&next.chunk_blob_digest);
            try next.encryption.write(writer);
        }

        pub inline fn read(reader: anytype) (@TypeOf(reader).Error || error{EndOfStream})!NextInfo {
            const chunk_blob_digest = try reader.readBytesNoEof(Sha256.digest_length);
            const encryption = try Encryption.read(reader);
            return .{
                .chunk_blob_digest = chunk_blob_digest,
                .encryption = encryption,
            };
        }
    };

    pub inline fn dataFlags(header: *const Header) DataFlags {
        return .{
            .full_file_digest = header.full_file_digest != null,
            .next = header.next != null,
        };
    }

    pub fn calcNameBuffer(header: *const Header, buffer: []const u8) [Sha256.digest_length]u8 {
        var hasher = Sha256.init(.{});
        const hasher_writer = util.sha256DigestCalcWriter(&hasher, std.io.null_writer).writer();
        writeHeader(header, hasher_writer) catch |err| switch (err) {};
        hasher.update(buffer);
        return hasher.finalResult();
    }

    /// Calculate the name of this chunk (SHA256 digest of the header + the chunk data).
    pub fn calcName(
        header: *const Header,
        /// Should be the reader passed to `readChunkHeader` to calculate the values of `header`, seeked
        /// back to the initial position before the `header` was calculated; that is to say, it should
        /// return the same data it returned during the aforementioned call to `readChunkHeader`.
        reader: anytype,
        /// `std.fifo.LinearFifo(u8, ...)`
        /// Used to pump the `reader` data through the SHA256 hash function
        fifo: anytype,
    ) @TypeOf(reader).Error![Sha256.digest_length]u8 {
        var hasher = Sha256.init(.{});
        const hasher_writer = util.sha256DigestCalcWriter(&hasher, std.io.null_writer).writer();
        writeHeader(hasher_writer, header) catch |err| switch (err) {};

        var limited = std.io.limitedReader(reader, chunk.size);
        try fifo.pump(limited.reader(), hasher_writer);

        return hasher.finalResult();
    }

    pub inline fn byteCount(header: *const Header) std.math.IntFittingRange(min_header_size, max_header_size) {
        const result = writeHeader(std.io.null_writer, header) catch |err| switch (err) {};
        return @intCast(result);
    }

    pub fn format(
        self: *const Header,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = fmt_str;
        try writer.print("{{ ver: {}, curr: {s}", .{
            self.version,
            digestBytesToString(&self.current_chunk_digest),
        });
        if (self.full_file_digest) |*full_digest| {
            try writer.print(", full: {s}", .{&digestBytesToString(full_digest)});
        }
        if (self.next) |*next| {
            try writer.print(", next_blob: {s}, next_enc: {}", .{ digestBytesToString(&next.chunk_blob_digest), next.encryption });
        }
        try writer.writeAll("}");
    }
};

pub const HeaderVersion = extern struct {
    major: u16,
    minor: u16,
    patch: u16,

    const latest: HeaderVersion = .{ .major = 0, .minor = 0, .patch = 0 };

    pub fn order(self: HeaderVersion, other: HeaderVersion) std.math.Order {
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

    pub fn format(
        version: HeaderVersion,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, version);
        try writer.print("{[major]d}.{[minor]d}.{[patch]d}", version);
    }

    inline fn toBytes(chv: HeaderVersion) [6]u8 {
        const le = HeaderVersion{
            .major = std.mem.nativeToLittle(u16, chv.major),
            .minor = std.mem.nativeToLittle(u16, chv.minor),
            .patch = std.mem.nativeToLittle(u16, chv.patch),
        };
        return @bitCast(le);
    }
    inline fn fromBytes(bytes: [6]u8) HeaderVersion {
        const le: HeaderVersion = @bitCast(bytes);
        return HeaderVersion{
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

    pub inline fn write(info: *const Encryption, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeAll(&info.tag);
        try writer.writeAll(&info.npub);
        try writer.writeAll(&info.key);
    }
    pub inline fn read(reader: anytype) (@TypeOf(reader).Error || error{EndOfStream})!Encryption {
        return .{
            .tag = try reader.readBytesNoEof(Aes256Gcm.tag_length),
            .npub = try reader.readBytesNoEof(Aes256Gcm.nonce_length),
            .key = try reader.readBytesNoEof(Aes256Gcm.key_length),
        };
    }

    pub fn format(
        self: *const Encryption,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        try writer.writeAll(".{ ");
        inline for (@typeInfo(Encryption).Struct.fields, 0..) |field, i| {
            if (i != 0) try writer.writeAll(", ");
            const field_ptr = &@field(self, field.name);
            try writer.writeAll(comptime std.fmt.comptimePrint(".{} = ", .{std.zig.fmtId(field.name)}));
            try std.fmt.formatType(std.fmt.fmtSliceHexLower(field_ptr), fmt_str, options, writer, std.fmt.default_max_depth);
        }
        try writer.writeAll(" }");
    }
};

pub fn writeHeader(
    writer: anytype,
    header: *const Header,
) @TypeOf(writer).Error!usize {
    var counter = std.io.countingWriter(writer);
    const cwriter = counter.writer();

    // write version
    try cwriter.writeAll(&header.version.toBytes());

    // write data flags
    try cwriter.writeByte(@bitCast(header.dataFlags()));

    // write the SHA of the current chunk's data
    try cwriter.writeAll(&header.current_chunk_digest);

    // write the full file SHA digest
    if (header.full_file_digest) |*ptr| try cwriter.writeAll(ptr);

    // write the encryption information for the next chunk
    if (header.next) |*ptr| try ptr.write(cwriter);

    return @intCast(counter.bytes_written);
}

pub const ReadHeaderError = error{
    UnrecognizedHeaderVersion,
    InvalidFirstChunkFlag,
};

pub fn readHeader(reader: anytype) (@TypeOf(reader).Error || error{EndOfStream} || ReadHeaderError)!Header {
    // read version
    const version: HeaderVersion = blk: {
        const bytes = try reader.readBytesNoEof(6);
        break :blk HeaderVersion.fromBytes(bytes);
    };
    switch (version.order(HeaderVersion.latest)) {
        .gt => return error.UnrecognizedHeaderVersion,
        .lt => @panic("This should not yet be possible"),
        .eq => {},
    }

    const data_flags: Header.DataFlags = @bitCast(try reader.readByte());

    // read the SHA of the current chunk's unencrypted data
    const current_chunk_digest: [Sha256.digest_length]u8 = try reader.readBytesNoEof(Sha256.digest_length);

    // read the SHA of the entire unencrypted file, if present
    const full_file_digest: ?[Sha256.digest_length]u8 = if (data_flags.full_file_digest)
        try reader.readBytesNoEof(Sha256.digest_length)
    else
        null;

    // read the info about the next chunk, if present
    const next: ?Header.NextInfo = if (data_flags.next)
        try Header.NextInfo.read(reader)
    else
        null;

    return .{
        .version = version,
        .current_chunk_digest = current_chunk_digest,
        .full_file_digest = full_file_digest,
        .next = next,
    };
}

pub const max_header_size: comptime_int = writeHeader(std.io.null_writer, &Header{
    .current_chunk_digest = .{0xFF} ** Sha256.digest_length,
    .full_file_digest = .{0xFF} ** Sha256.digest_length,
    .next = .{
        .chunk_blob_digest = .{0xFF} ** Sha256.digest_length,
        .encryption = .{
            .tag = .{0xFF} ** Aes256Gcm.tag_length,
            .npub = .{0xFF} ** Aes256Gcm.nonce_length,
            .key = .{0xFF} ** Aes256Gcm.key_length,
        },
    },
}) catch |err| @compileError(@errorName(err));

pub const min_header_size: comptime_int = writeHeader(std.io.null_writer, &Header{
    .version = .{ .major = 0, .minor = 0, .patch = 0 },
    .current_chunk_digest = .{0} ** Sha256.digest_length,
    .full_file_digest = null,
    .next = null,
}) catch |err| @compileError(@errorName(err));

test Header {
    try testChunkHeader(.{
        .current_chunk_digest = try comptime digestStringToBytes("Cd" ** Sha256.digest_length),
        .full_file_digest = null,
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
        .full_file_digest = null,
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
        .full_file_digest = null,
        .next = null,
    });

    {
        var fbs = std.io.fixedBufferStream("");
        try std.testing.expectError(error.EndOfStream, readHeader(fbs.reader()));
        try std.testing.expectError(error.EndOfStream, readHeader(fbs.reader()));
        try std.testing.expectError(error.EndOfStream, readHeader(fbs.reader()));
    }
}

fn testChunkHeader(ch: Header) !void {
    var bytes = std.BoundedArray(u8, max_header_size){};
    _ = try writeHeader(bytes.writer(), &ch);

    var fbs = std.io.fixedBufferStream(bytes.constSlice());
    const actual = try readHeader(fbs.reader());
    try std.testing.expectEqual(ch, actual);
}