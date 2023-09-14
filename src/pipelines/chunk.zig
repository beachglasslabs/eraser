const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

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
    return @as(u64, chunk_idx) * size;
}

pub const Header = struct {
    version: HeaderVersion = HeaderVersion.latest,
    /// Should be the SHA of the blob comprised of the next chunk's header and data.
    /// If this is for the last chunk, it should simply be the SHA of the last chunk.
    next_chunk_blob_digest: [Sha256.digest_length]u8,
    /// Should be the SHA of the current chunk's data.
    current_chunk_digest: [Sha256.digest_length]u8,
    /// Should be non-`null` for the first chunk.
    full_file_digest: ?[Sha256.digest_length]u8,

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

        var limited = std.io.limitedReader(reader, size);
        try fifo.pump(limited.reader(), hasher_writer);

        return hasher.finalResult();
    }

    pub inline fn byteCount(header: *const Header) std.math.IntFittingRange(min_header, max_header) {
        var counter = std.io.countingWriter(std.io.null_writer);
        writeHeader(counter.writer(), header) catch |err| switch (err) {};
        return @intCast(counter.bytes_written);
    }

    pub fn format(
        ch: Header,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, ch);
        _ = options;
        try writer.print("{}\r\n", .{ch.version});
        try writer.print("this: {s}\r\n", .{&digestBytesToString(&ch.current_chunk_digest)});
        try writer.print("next: {s}\r\n", .{&digestBytesToString(&ch.next_chunk_blob_digest)});
        if (ch.full_file_digest) |*full|
            try writer.print("full: {s}\r\n", .{&digestBytesToString(full)});
    }
};

pub const HeaderVersion = extern struct {
    major: u16,
    minor: u16,
    patch: u16,

    const latest: HeaderVersion = .{ .major = 0, .minor = 0, .patch = 1 };

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

pub fn writeHeader(
    writer: anytype,
    header: *const Header,
) @TypeOf(writer).Error!void {
    // write version
    try writer.writeAll(&header.version.toBytes());

    // write the SHA of the next chunk's header and data
    try writer.writeAll(&header.next_chunk_blob_digest);

    // write the SHA of the current' chunk's data
    try writer.writeAll(&header.current_chunk_digest);

    // write first chunk flag
    try writer.writeByte(@intFromBool(header.full_file_digest != null));

    // if this is the first chunk, write the full file SHA
    if (header.full_file_digest) |*digest| {
        try writer.writeAll(digest);
    }
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

    // read the SHA of the next chunk's header and data
    const next_chunk_blob_digest = try reader.readBytesNoEof(Sha256.digest_length);

    // read the SHA of the current chunk's data
    const current_chunk_digest = try reader.readBytesNoEof(Sha256.digest_length);

    // read the first chunk flag
    const first_chunk_flag: bool = switch (try reader.readByte()) {
        0 => false,
        1 => true,
        else => return error.InvalidFirstChunkFlag,
    };

    // if this is the first chunk, read the full file SHA
    const full_file_digest: ?[Sha256.digest_length]u8 = if (first_chunk_flag) blk: {
        break :blk try reader.readBytesNoEof(Sha256.digest_length);
    } else null;

    // TODO: see the TODO in `writeChunkHeader` about 'The sha(A + B) and sha(sha(A + B) + sha(C + D))'

    return .{
        .version = version,
        .next_chunk_blob_digest = next_chunk_blob_digest,
        .current_chunk_digest = current_chunk_digest,
        .full_file_digest = full_file_digest,
    };
}

const max_header: comptime_int = blk: {
    var counter = std.io.countingWriter(std.io.null_writer);
    writeHeader(counter.writer(), &Header{
        .next_chunk_blob_digest = .{0xFF} ** Sha256.digest_length,
        .current_chunk_digest = .{0xFF} ** Sha256.digest_length,
        .full_file_digest = .{0xFF} ** Sha256.digest_length,
    }) catch |err| @compileError(@errorName(err));
    break :blk counter.bytes_written;
};

const min_header: comptime_int = blk: {
    var counter = std.io.countingWriter(std.io.null_writer);
    writeHeader(counter.writer(), &Header{
        .version = .{ .major = 0, .minor = 0, .patch = 0 },
        .next_chunk_blob_digest = .{0} ** Sha256.digest_length,
        .current_chunk_digest = .{0} ** Sha256.digest_length,
        .full_file_digest = null,
    }) catch |err| @compileError(@errorName(err));
    break :blk counter.bytes_written;
};

fn testChunkHeader(ch: Header) !void {
    var bytes = std.BoundedArray(u8, max_header){};
    try writeHeader(bytes.writer(), &ch);

    var fbs = std.io.fixedBufferStream(bytes.constSlice());
    const actual = try readHeader(fbs.reader());
    try std.testing.expectEqual(ch, actual);
}

test Header {
    try testChunkHeader(.{
        .next_chunk_blob_digest = try comptime digestStringToBytes("aB" ** Sha256.digest_length),
        .current_chunk_digest = try comptime digestStringToBytes("Cd" ** Sha256.digest_length),
        .full_file_digest = try comptime digestStringToBytes("eF" ** Sha256.digest_length),
    });
    try testChunkHeader(.{
        .next_chunk_blob_digest = try comptime digestStringToBytes("Ab" ** Sha256.digest_length),
        .current_chunk_digest = try comptime digestStringToBytes("cD" ** Sha256.digest_length),
        .full_file_digest = null,
    });
}
