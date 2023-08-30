const std = @import("std");
const mulWide = std.math.mulWide;
const assert = std.debug.assert;

const util = @import("util.zig");
const galois = @import("galois.zig");
const BinaryFieldMatrix = @import("BinaryFieldMatrix.zig");

pub fn roundByteSize(comptime T: type) comptime_int {
    return @bitSizeOf(T) / @bitSizeOf(u8);
}
comptime {
    assert(roundByteSize(u64) == @sizeOf(u64));
}

pub const IndexSet = BinaryFieldMatrix.IndexSet;
pub const ReadState = enum { done, in_progress };

pub fn ErasureCoder(comptime T: type) type {
    assert(@typeInfo(T) == .Int);
    return struct {
        bf_mat: BinaryFieldMatrix,

        encoder_bf_mat_bin: BinaryFieldMatrix,

        decoder_buf_full_allocation: []u8,

        decoder_sub_mat_buf: []u8,
        decoder_mat_inv_buf: []u8,
        decoder_mat_bin_buf: []u8,
        decoder_mat_bin_tmp_buf: []u8,

        block_buffer: []T,
        const Self = @This();

        pub const word_size = roundByteSize(T);
        const Exp = galois.BinaryField.Exp;

        pub const ReadOutput = struct {
            block: []T,
            state: ReadState,
        };

        pub fn init(allocator: std.mem.Allocator, shard_count: u7, shard_size: u7) !Self {
            const exp = try calcGaloisFieldExponent(shard_count, shard_size);

            const bf_mat = try BinaryFieldMatrix.initCauchy(allocator, shard_count, shard_size, exp);
            errdefer bf_mat.deinit(allocator);

            const encoder_bf_mat_bin = try bf_mat.toBinary(allocator);
            errdefer encoder_bf_mat_bin.deinit(allocator);

            const decoder_buf_full_alloc = try allocator.alloc(
                u8,
                @as(usize, 0) +
                    bf_mat.matrix.getCellCount() +
                    bf_mat.matrix.getCellCount() +
                    bf_mat.toBinaryCellCount() +
                    bf_mat.toBinaryTempBufCellCount(),
            );
            errdefer allocator.free(decoder_buf_full_alloc);

            var decoder_buf_fba_state = std.heap.FixedBufferAllocator.init(decoder_buf_full_alloc);
            const decoder_buf_fba = decoder_buf_fba_state.allocator();

            const decoder_sub_mat_buf = decoder_buf_fba.alloc(u8, bf_mat.matrix.getCellCount()) catch unreachable;
            const decoder_mat_inv_buf = decoder_buf_fba.alloc(u8, bf_mat.matrix.getCellCount()) catch unreachable;
            const decoder_mat_bin_buf = decoder_buf_fba.alloc(u8, bf_mat.toBinaryCellCount()) catch unreachable;
            const decoder_mat_bin_tmp_buf = decoder_buf_fba.alloc(u8, bf_mat.toBinaryTempBufCellCount()) catch unreachable;

            decoder_buf_fba_state = undefined;

            const block_buffer = try allocator.alloc(T, mulWide(u8, exp, shard_size));
            errdefer allocator.free(block_buffer);

            return .{
                .bf_mat = bf_mat,

                .encoder_bf_mat_bin = encoder_bf_mat_bin,

                .decoder_buf_full_allocation = decoder_buf_full_alloc,
                .decoder_sub_mat_buf = decoder_sub_mat_buf,
                .decoder_mat_inv_buf = decoder_mat_inv_buf,
                .decoder_mat_bin_buf = decoder_mat_bin_buf,
                .decoder_mat_bin_tmp_buf = decoder_mat_bin_tmp_buf,

                .block_buffer = block_buffer,
            };
        }

        pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
            allocator.free(self.block_buffer);

            allocator.free(self.decoder_buf_full_allocation);

            self.encoder_bf_mat_bin.deinit(allocator);
            self.bf_mat.deinit(allocator);
        }

        pub inline fn exponent(self: Self) Exp {
            return self.bf_mat.field.exponent();
        }
        pub inline fn shardCount(self: Self) u7 {
            return @intCast(self.bf_mat.matrix.numRows());
        }
        pub inline fn shardSize(self: Self) u7 {
            return @intCast(self.bf_mat.matrix.numCols());
        }

        const ChunkSize = std.math.IntFittingRange(0, roundByteSize(T) * std.math.maxInt(Exp));
        pub inline fn chunkSize(self: Self) ChunkSize {
            return calcChunkSize(word_size, self.exponent());
        }

        pub inline fn codeBlockSize(self: Self) u8 {
            return calcCodeBlockSize(self.chunkSize(), self.shardCount());
        }

        pub inline fn dataBlockSize(self: Self) u8 {
            return calcDataBlockSize(self.chunkSize(), self.shardSize());
        }

        pub fn encode(
            self: Self,
            /// `std.io.Reader(...)`
            in_fifo_reader: anytype,
            /// `[]const std.io.Writer(...)`
            out_fifo_writers: anytype,
        ) !usize {
            var size: usize = 0;
            while (true) {
                const data_block = self.block_buffer;
                const rs = try readDataBlock(T, data_block, in_fifo_reader);
                try writeCodeBlock(T, self.encoder_bf_mat_bin, data_block, out_fifo_writers, .{
                    .shard_count = self.shardCount(),
                    .shard_size = self.shardSize(),
                });
                switch (rs) {
                    .in_progress => size += calcDataBlockSize(calcChunkSize(word_size, self.exponent()), self.shardSize()),
                    .done => {
                        var buffer = [_]u8{0} ** word_size;
                        std.mem.writeIntBig(T, &buffer, data_block[data_block.len - 1]);
                        size += buffer[buffer.len - 1];
                        break;
                    },
                }
            }
            return size;
        }

        pub fn decode(
            self: Self,
            excluded_shards: IndexSet,
            /// `[]const std.io.Reader(...)`
            in_fifos: anytype,
            /// `std.io.Writer(...)`
            out_fifo_writer: anytype,
        ) !usize {
            assert(excluded_shards.count() == self.shardCount() - self.shardSize());
            assert(in_fifos.len == self.shardSize());

            const decoder_bin = blk: {
                const decoder_sub_buf = self.decoder_sub_mat_buf[0..self.bf_mat.subMatrixCellCount(excluded_shards, IndexSet{})];
                const decoder_sub = self.bf_mat.subMatrixWith(decoder_sub_buf, excluded_shards, IndexSet{});

                const decoder_inv_buf = self.decoder_mat_inv_buf[0..decoder_sub.matrix.getCellCount()];
                const decoder_inv = try decoder_sub.invertWith(decoder_inv_buf);

                const decoder_bin_buf = self.decoder_mat_bin_buf[0..decoder_inv.toBinaryCellCount()];
                const decoder_bin_tmp_buf = self.decoder_mat_bin_tmp_buf[0..decoder_inv.toBinaryTempBufCellCount()];

                break :blk try decoder_inv.toBinaryWith(decoder_bin_buf, decoder_bin_tmp_buf);
            };

            var tail_bytes: ?[word_size]u8 = null;
            var size: usize = 0;
            while (true) {
                const block = self.block_buffer;
                tail_bytes = try readCodeBlock(T, self.exponent(), block, in_fifos, tail_bytes);
                const write_size = try writeDataBlock(T, out_fifo_writer, .{
                    .decoder = decoder_bin,
                    .code_block = block,
                    .done = tail_bytes == null,
                });
                size += write_size;
                if (tail_bytes == null) break;
            }

            return size;
        }
    };
}

/// Reads a data block, with the full data block size
/// being `block.len * roundByteSize(Word)`.
pub fn readDataBlock(
    comptime Word: type,
    block: []Word,
    /// `std.io.Reader(...)`
    data_reader: anytype,
) @TypeOf(data_reader).Error!ReadState {
    const word_size = roundByteSize(Word);
    @memset(block, 0);
    const data_block_size = block.len * word_size;
    var block_size: u8 = 0;

    for (block) |*block_int| {
        var buffer = [_]u8{0} ** word_size;
        const read_size = try data_reader.readAll(&buffer);
        block_size += @intCast(read_size);

        if (read_size < buffer.len) {
            buffer[buffer.len - 1] = block_size;
        }
        const new_value = std.mem.readIntBig(Word, &buffer);
        block_int.* = new_value;

        if (read_size == 0) {
            // we only end up reading the very last word of the block to decode the block size
            block[block.len - 1] = new_value;
            break;
        }
    }

    if (block_size < data_block_size)
        return .done;
    return .in_progress;
}

pub fn writeCodeBlock(
    comptime Word: type,
    encoder: BinaryFieldMatrix,
    data_block: []const Word,
    /// `[]const std.io.Writer(...)`
    out_fifos: anytype,
    values: struct {
        shard_count: u7,
        shard_size: u7,
    },
) !void {
    const exp: galois.BinaryField.Exp = calcGaloisFieldExponent(values.shard_count, values.shard_size) catch unreachable;
    assert(@divExact(data_block.len, values.shard_size) == exp);

    var index: u7 = 0;
    while (index != exp * values.shard_count) : (index += 1) {
        var value: Word = 0;

        var j: u8 = 0;
        while (j < encoder.numCols()) : (j += 1) {
            if (encoder.get(.{ .row = index, .col = j }) == 1) {
                value ^= data_block[j];
            }
        }

        const word_size = roundByteSize(Word);
        const word: [word_size]u8 = @bitCast(std.mem.nativeToBig(Word, value));
        const out_idx = index / exp;
        try out_fifos[out_idx].writeAll(&word);
    }
}

/// Returns null if reading is finished.
/// Otherwise returns the last bytes read from the reader at index `(block.len - 1) / exp`.
/// These returned bytes should be passed as the `last_bytes_from_prev_call` parameter on a subsequent call.
pub fn readCodeBlock(
    comptime Word: type,
    exp: galois.BinaryField.Exp,
    block: []Word,
    /// `[]const std.io.Reader(...)`
    in_peek_stream_slice: anytype,
    /// `null` if this is the first call, otherwise
    /// this should be the result from the previous call to this function.
    last_bytes_from_prev_call: ?[roundByteSize(Word)]u8,
) !?[roundByteSize(Word)]u8 {
    @memset(block, 0);
    const word_size = roundByteSize(Word);

    var maybe_last_reader_bytes = last_bytes_from_prev_call;

    const last_reader_idx = (block.len - 1) / exp;
    const last_peek_stream = &in_peek_stream_slice[last_reader_idx];
    assert(in_peek_stream_slice.len == last_reader_idx + 1);

    for (block, 0..) |*block_int, i| {
        var buffer = [_]u8{0} ** word_size;
        const reader_idx = i / exp;

        const use_prev_bytes =
            reader_idx == last_reader_idx and
            maybe_last_reader_bytes != null;
        if (use_prev_bytes) {
            buffer = maybe_last_reader_bytes.?;
            maybe_last_reader_bytes = null;
        } else {
            const read_size = try in_peek_stream_slice[reader_idx].readAll(&buffer);
            assert(read_size == buffer.len);
        }

        block_int.* = std.mem.readIntBig(Word, &buffer);
    }

    var buffer = [_]u8{0} ** word_size;
    const size = try last_peek_stream.readAll(&buffer);

    return switch (size) {
        0 => null,
        word_size => buffer,
        else => unreachable,
    };
}

pub fn writeDataBlock(
    comptime T: type,
    /// `std.io.Writer(...)`
    out_fifo_writer: anytype,
    params: struct {
        decoder: BinaryFieldMatrix,
        code_block: []const T,
        done: bool,
    },
) !usize {
    const word_size = roundByteSize(T);
    const full_data_block_size: u8 = @intCast(params.code_block.len * word_size);

    const data_block_size: u8 = if (!params.done) full_data_block_size else blk: {
        const i: u8 = @intCast(params.code_block.len - 1);

        var val: T = 0;
        for (params.code_block, 0..params.decoder.numCols()) |code_byte, j| {
            if (params.decoder.get(.{ .row = i, .col = @intCast(j) }) == 1) {
                val ^= code_byte;
            }
        }

        var buf = [_]u8{0} ** word_size;
        std.mem.writeIntBig(T, &buf, val);
        break :blk buf[buf.len - 1];
    };

    var written_size: usize = 0;
    for (0..params.code_block.len) |i| {
        var val: T = 0;
        for (params.code_block, 0..params.decoder.numCols()) |code_byte, j| {
            if (params.decoder.get(.{ .row = @intCast(i), .col = @intCast(j) }) == 1) {
                val ^= code_byte;
            }
        }

        var word = [_]u8{0} ** word_size;
        std.mem.writeIntBig(T, &word, val);

        if ((written_size + word.len) <= data_block_size) {
            try out_fifo_writer.writeAll(&word);
            written_size += word.len;
        } else {
            try out_fifo_writer.writeAll(word[0..(data_block_size - written_size)]);
            written_size = data_block_size;
            break;
        }
    }

    return data_block_size;
}

inline fn calcGaloisFieldExponent(shard_count: u7, shard_size: u7) error{ ShardSizePlusCountOverflow, ZeroShards, ZeroSize }!galois.BinaryField.Exp {
    if (shard_count == 0) return error.ZeroShards;
    if (shard_size == 0) return error.ZeroSize;

    const count_plus_size = @as(u8, shard_count) + shard_size;
    if (count_plus_size >= galois.BinaryField.order(.degree7)) {
        return error.ShardSizePlusCountOverflow;
    }

    const ceil_log2 = std.math.log2_int_ceil(u8, count_plus_size);
    return @intCast(ceil_log2);
}

inline fn calcChunkSize(
    /// Size of each word in a block.
    word_size: anytype,
    /// Exponent of the finite binary field of order `2^exp`.
    exp: anytype,
) T: {
    const Ws = @TypeOf(word_size);
    const Exp = @TypeOf(exp);
    const max_ws = if (Ws == comptime_int) word_size else std.math.maxInt(Ws);
    const max_exp = if (Exp == comptime_int) exp else std.math.maxInt(Exp);
    break :T std.math.IntFittingRange(0, max_ws * max_exp);
} {
    const Ws = @TypeOf(word_size);
    const Exp = @TypeOf(exp);

    const max_ws = if (Ws == comptime_int) word_size else std.math.maxInt(Ws);
    const max_exp = if (Exp == comptime_int) exp else std.math.maxInt(Exp);

    const T = std.math.IntFittingRange(0, max_ws * max_exp);
    return @as(T, word_size) * exp;
}

inline fn calcCodeBlockSize(
    /// Size of each chunk, likely calculated using `calcChunkSize`.
    chunk_size: anytype,
    shard_count: u8,
) u8 {
    return chunk_size * shard_count;
}
inline fn calcDataBlockSize(
    /// Size of each chunk, likely calculated using `calcChunkSize`.
    chunk_size: anytype,
    shard_size: u8,
) u8 {
    return chunk_size * shard_size;
}

pub fn sampleIndexSet(
    /// It is advisable to use a Pseudo-RNG here, and not a true RNG,
    /// given the use of `uintLessThan`. See the doc comment on that
    /// function for commentary on the runtime of this function.
    random: std.rand.Random,
    /// The maximum index value. For the result it will hold true
    /// `result.count() < max`, and the highest bit that would be
    /// set is `max - 1`.
    max: u8,
    /// The number of index values to generate.
    num: u8,
) IndexSet {
    var set = IndexSet{};
    while (set.count() < num) {
        const new = random.uintLessThan(u8, max);
        set.set(new);
    }
    return set;
}

test "erasure coder" {
    const test_data = [_][]const u8{
        "The quick brown fox jumps over the lazy dog.",
        "All your base are belong to us.",
        "All work and no play makes Jack a dull boy.",
        "Whoever fights monsters should see to it that in the process he does not become a monster.\nAnd if you gaze long enough into an abyss, the abyss will gaze back into you.",
    };

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var prng = std.rand.DefaultPrng.init(1234);
    var random = prng.random();

    for (test_data) |data| {
        const data_filename = "temp_data_file";

        var data_file = try tmp.dir.createFile(data_filename, .{});
        try data_file.writer().writeAll(data);
        data_file.close();
        defer tmp.dir.deleteFile(data_filename) catch {};

        inline for ([_]type{ u8, u16, u32, u64 }) |T| {
            const code_filenames = [5][]const u8{
                "temp_code_file_1",
                "temp_code_file_2",
                "temp_code_file_3",
                "temp_code_file_4",
                "temp_code_file_5",
            };

            var ec = try ErasureCoder(T).init(std.testing.allocator, code_filenames.len, 3);
            defer ec.deinit(std.testing.allocator);

            const data_size = encode: {
                var code_files: [code_filenames.len]std.fs.File = undefined;
                for (code_files[0..], code_filenames, 0..) |*cf, cf_name, end| {
                    errdefer for (code_files[0..end]) |prev| prev.close();
                    cf.* = try tmp.dir.createFile(cf_name, .{});
                }
                defer for (code_files) |cf| cf.close();

                var code_writers: [5]std.fs.File.Writer = undefined;
                for (code_writers[0..], code_files[0..]) |*cw, cf| {
                    cw.* = cf.writer();
                }

                const data_in = try tmp.dir.openFile(data_filename, .{});
                defer data_in.close();

                break :encode try ec.encode(data_in.reader(), &code_writers);
            };
            try std.testing.expect(data_size > 0);

            decode: {
                const excluded_shards = sampleIndexSet(random, 5, 2);

                var code_in: [3]std.fs.File = undefined;
                var code_readers: [3]std.fs.File.Reader = undefined;

                var j: usize = 0;
                for (code_filenames, 0..) |code_filename, i| {
                    if (excluded_shards.isSet(@intCast(i))) continue;
                    code_in[j] = try tmp.dir.openFile(code_filename, .{});
                    code_readers[j] = code_in[j].reader();
                    j += 1;
                }

                const decoded_filename = "temp_decoded_data_file";

                const decoded_file = try tmp.dir.createFile(decoded_filename, .{});
                defer decoded_file.close();

                const decoded_size = try ec.decode(excluded_shards, &code_readers, decoded_file.writer());
                for (code_in) |f| f.close();
                try tmp.dir.deleteFile(decoded_filename);

                try std.testing.expectEqual(data_size, decoded_size);
                var buffer = std.mem.zeroes([256]u8);
                var decoded_in = try tmp.dir.openFile(data_filename, .{});
                defer decoded_in.close();
                var buffer_size = try decoded_in.reader().readAll(&buffer);
                try std.testing.expectEqualSlices(u8, data, buffer[0..buffer_size]);

                break :decode;
            }
        }
    }
}
