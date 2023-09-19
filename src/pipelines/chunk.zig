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
const bytes_per_megabyte = 10_000_000;

pub const Count = std.math.IntFittingRange(1, std.math.maxInt(u64) / chunk.size);
pub inline fn countForFileSize(file_size: u64) std.math.IntFittingRange(1, std.math.maxInt(u64) / chunk.size) {
    return @intCast(file_size / chunk.size + 1);
}
pub inline fn startOffset(chunk_idx: Count) u64 {
    return (@as(u64, chunk_idx) * size);
}

pub const Header = struct {
    version: HeaderVersion = HeaderVersion.latest,
    /// Should be the SHA of the current chunk's data.
    current_chunk_digest: [Sha256.digest_length]u8,
    /// Should be the SHA of the blob comprised of the next chunk's header and data.
    /// If this is for the last chunk, it should simply be the SHA of the last chunk.
    next_chunk_blob_digest: [Sha256.digest_length]u8,
    /// Grouping of possible data states based on if this is the header of the first
    /// chunk, the last chunk, or a chunk in between the first and last chunks.
    ordered_data: OrderedData,

    pub const OrderedData = union(enum) {
        first: First,
        middle: Middle,
        last: Last,

        pub const First = struct {
            full_file_digest: [Sha256.digest_length]u8,
            next_encryption: EncryptionInfo,
        };
        pub const Middle = struct {
            next_encryption: EncryptionInfo,
        };
        pub const Last = struct {};
    };

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

pub const EncryptionInfo = struct {
    auth_tag: [Aes256Gcm.tag_length]u8,
    npub: [Aes256Gcm.nonce_length]u8,
    key: [Aes256Gcm.key_length]u8,

    pub inline fn write(info: *const EncryptionInfo, writer: anytype) @TypeOf(writer).Error!void {
        try writer.writeAll(&info.auth_tag);
        try writer.writeAll(&info.npub);
        try writer.writeAll(&info.key);
    }
    pub inline fn read(reader: anytype) (@TypeOf(reader).Error || error{EndOfStream})!EncryptionInfo {
        return .{
            .auth_tag = try reader.readBytesNoEof(Aes256Gcm.tag_length),
            .npub = try reader.readBytesNoEof(Aes256Gcm.nonce_length),
            .key = try reader.readBytesNoEof(Aes256Gcm.key_length),
        };
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

    // write the SHA of the current chunk's data
    try cwriter.writeAll(&header.current_chunk_digest);

    // write the SHA of the header and data of the next chunk
    try cwriter.writeAll(&header.next_chunk_blob_digest);

    switch (header.ordered_data) {
        .first => |*data| {
            // write the SHA of the entire file
            try cwriter.writeAll(&data.full_file_digest);
            // write the encryption info of the next chunk
            try data.next_encryption.write(cwriter);
        },
        .middle => |*data| {
            // write the encryption info of the next chunk
            try data.next_encryption.write(cwriter);
        },
        .last => {},
    }

    return @intCast(counter.bytes_written);
}

pub const ReadHeaderError = error{
    UnrecognizedHeaderVersion,
    InvalidFirstChunkFlag,
};

pub const ReadOrder = enum {
    /// Specify when reading the first chunk
    first,
    /// Specify when reading any chunk after the first and before the last
    middle,
    /// Specify when reading the last chunk
    last,
};
pub fn readHeader(
    reader: anytype,
    read_order: ReadOrder,
) (@TypeOf(reader).Error || error{EndOfStream} || ReadHeaderError)!Header {
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

    // read the SHA of the current chunk's data
    const current_chunk_digest = try reader.readBytesNoEof(Sha256.digest_length);

    // read the SHA of the next chunk's header and data
    const next_chunk_blob_digest = try reader.readBytesNoEof(Sha256.digest_length);

    const ordered_data: Header.OrderedData = switch (read_order) {
        .first => .{ .first = .{
            .full_file_digest = try reader.readBytesNoEof(Sha256.digest_length),
            .next_encryption = try EncryptionInfo.read(reader),
        } },
        .middle => .{ .middle = .{
            .next_encryption = try EncryptionInfo.read(reader),
        } },
        .last => .{ .last = .{} },
    };

    return .{
        .version = version,
        .next_chunk_blob_digest = next_chunk_blob_digest,
        .current_chunk_digest = current_chunk_digest,
        .ordered_data = ordered_data,
    };
}

pub const max_header_size: comptime_int = writeHeader(std.io.null_writer, &Header{
    .next_chunk_blob_digest = .{0xFF} ** Sha256.digest_length,
    .current_chunk_digest = .{0xFF} ** Sha256.digest_length,
    .ordered_data = data: {
        // name of the largest field
        const name_of_max = blk: {
            const fields = @typeInfo(Header.OrderedData).Union.fields;
            var max_idx = 0;
            var max_size = @sizeOf(fields[0].type);
            for (fields, 0..) |field, i| {
                const field_size = @sizeOf(field.type);
                if (max_size >= field_size) continue;
                max_size = field_size;
                max_idx = i;
            }
            break :blk fields[max_idx].name;
        };

        const max_encryption = EncryptionInfo{
            .auth_tag = .{0xFF} ** Aes256Gcm.tag_length,
            .npub = .{0xFF} ** Aes256Gcm.nonce_length,
            .key = .{0xFF} ** Aes256Gcm.key_length,
        };
        const data = switch (@field(std.meta.FieldEnum(Header.OrderedData), name_of_max)) {
            .first => Header.OrderedData.First{
                .full_file_digest = .{0xFF} ** Sha256.digest_length,
                .next_encryption = max_encryption,
            },
            .middle => Header.OrderedData.Middle{
                .next_encryption = max_encryption,
            },
            .last => Header.OrderedData.Last{},
        };
        break :data @unionInit(Header.OrderedData, name_of_max, data);
    },
}) catch |err| @compileError(@errorName(err));

pub const min_header_size: comptime_int = writeHeader(std.io.null_writer, &Header{
    .version = .{ .major = 0, .minor = 0, .patch = 0 },
    .next_chunk_blob_digest = .{0} ** Sha256.digest_length,
    .current_chunk_digest = .{0} ** Sha256.digest_length,
    .ordered_data = .{
        .last = @as(Header.OrderedData.Last, blk: {
            assert(@sizeOf(Header.OrderedData.Last) == 0); // nothing smaller than 0 bytes
            break :blk .{};
        }),
    },
}) catch |err| @compileError(@errorName(err));

test Header {
    try testChunkHeader(.{
        .next_chunk_blob_digest = try comptime digestStringToBytes("aB" ** Sha256.digest_length),
        .current_chunk_digest = try comptime digestStringToBytes("Cd" ** Sha256.digest_length),
        .ordered_data = .{ .first = .{
            .full_file_digest = try comptime digestStringToBytes("eF" ** Sha256.digest_length),
            .next_encryption = .{
                .auth_tag = .{7} ** Aes256Gcm.tag_length,
                .npub = .{15} ** Aes256Gcm.nonce_length,
                .key = .{32} ** Aes256Gcm.key_length,
            },
        } },
    });
    try testChunkHeader(.{
        .next_chunk_blob_digest = try comptime digestStringToBytes("Ab" ** Sha256.digest_length),
        .current_chunk_digest = try comptime digestStringToBytes("cD" ** Sha256.digest_length),
        .ordered_data = .{ .middle = .{
            .next_encryption = .{
                .auth_tag = .{7} ** Aes256Gcm.tag_length,
                .npub = .{15} ** Aes256Gcm.nonce_length,
                .key = .{32} ** Aes256Gcm.key_length,
            },
        } },
    });
    try testChunkHeader(.{
        .next_chunk_blob_digest = try comptime digestStringToBytes("aB" ** Sha256.digest_length),
        .current_chunk_digest = try comptime digestStringToBytes("Cd" ** Sha256.digest_length),
        .ordered_data = .{ .last = .{} },
    });

    {
        var fbs = std.io.fixedBufferStream("");
        try std.testing.expectError(error.EndOfStream, readHeader(fbs.reader(), .first));
        try std.testing.expectError(error.EndOfStream, readHeader(fbs.reader(), .middle));
        try std.testing.expectError(error.EndOfStream, readHeader(fbs.reader(), .last));
    }
}

fn testChunkHeader(ch: Header) !void {
    const read_order: ReadOrder = switch (ch.ordered_data) {
        .first => .first,
        .middle => .middle,
        .last => .last,
    };
    var bytes = std.BoundedArray(u8, max_header_size){};
    _ = try writeHeader(bytes.writer(), &ch);

    var fbs = std.io.fixedBufferStream(bytes.constSlice());
    const actual = try readHeader(fbs.reader(), read_order);
    try std.testing.expectEqual(ch, actual);
}
