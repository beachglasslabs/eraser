const std = @import("std");
const mulWide = std.math.mulWide;
const assert = std.debug.assert;

const util = @import("util.zig");
const BinaryFiniteField = @import("BinaryFiniteField.zig");
const BinaryFieldMatrix = @import("BinaryFieldMatrix.zig");

fn roundByteSize(comptime T: type) comptime_int {
    return @bitSizeOf(T) / @bitSizeOf(u8);
}

pub const IndexSet = BinaryFieldMatrix.IndexSet;
pub const ReadState = enum { done, in_progress };

pub fn ErasureCoder(comptime T: type) type {
    assert(@typeInfo(T) == .Int);
    return struct {
        bf_mat: BinaryFieldMatrix,

        // TODO: look into making all of these separate allocations into a single
        // allocation to reduce fragmentation, and reduce cache contention.
        encoder_bf_mat_bin: BinaryFieldMatrix,

        decoder_bf_sub_mat_buf: []align(16) u8,
        decoder_bf_mat_inv_buf: []align(16) u8,
        decoder_bf_mat_bin_buf: []align(16) u8,
        decoder_bf_mat_bin_tmp_buf: []align(16) u8,

        block_buffer: []T,
        word_buffer: [][word_size]u8,
        streams_buffer: []align(@alignOf(*anyopaque)) u8,
        const Self = @This();

        pub const word_size = roundByteSize(T);
        const Exp = BinaryFiniteField.Exp;

        pub const ReadOutput = struct {
            block: []T,
            state: ReadState,
        };

        pub fn init(allocator: std.mem.Allocator, shard_count: u8, shard_size: u8) !Self {
            const exp = try calcExponent(shard_count, shard_size);

            const bf_mat = try BinaryFieldMatrix.initCauchy(allocator, shard_count, shard_size, exp);
            errdefer bf_mat.deinit(allocator);

            const encoder_bf_mat_bin = try bf_mat.toBinary(allocator);
            errdefer encoder_bf_mat_bin.deinit(allocator);

            const decoder_bf_sub_mat_buf = try allocator.alignedAlloc(u8, 16, bf_mat.matrix.getCellCount());
            errdefer allocator.free(decoder_bf_sub_mat_buf);

            const decoder_bf_mat_inv_buf = try allocator.alignedAlloc(u8, 16, bf_mat.matrix.getCellCount());
            errdefer allocator.free(decoder_bf_mat_inv_buf);

            const decoder_bf_mat_bin_buf = try allocator.alignedAlloc(u8, 16, bf_mat.toBinaryCellCount());
            errdefer allocator.free(decoder_bf_mat_bin_buf);

            const decoder_bf_mat_bin_tmp_buf = try allocator.alignedAlloc(u8, 16, bf_mat.toBinaryTempBufCellCount());
            errdefer allocator.free(decoder_bf_mat_bin_tmp_buf);

            const block_buffer = try allocator.alloc(T, mulWide(u8, exp, shard_size));
            errdefer allocator.free(block_buffer);

            const word_buffer = try allocator.alloc([word_size]u8, mulWide(u8, exp, shard_size));
            errdefer allocator.free(word_buffer);

            const MinReader = util.PtrSizedReader(std.fs.File.Reader);
            const MinPeekStream = std.io.PeekStream(.{ .Static = word_size }, MinReader);
            const min_stream_size: usize = @sizeOf(MinPeekStream);

            const streams_buffer = try allocator.alignedAlloc(u8, @alignOf(*anyopaque), min_stream_size * shard_size);
            errdefer allocator.free(streams_buffer);

            return .{
                .bf_mat = bf_mat,

                .encoder_bf_mat_bin = encoder_bf_mat_bin,
                .decoder_bf_sub_mat_buf = decoder_bf_sub_mat_buf,
                .decoder_bf_mat_inv_buf = decoder_bf_mat_inv_buf,
                .decoder_bf_mat_bin_buf = decoder_bf_mat_bin_buf,
                .decoder_bf_mat_bin_tmp_buf = decoder_bf_mat_bin_tmp_buf,

                .block_buffer = block_buffer,
                .word_buffer = word_buffer,
                .streams_buffer = streams_buffer,
            };
        }

        pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
            allocator.free(self.streams_buffer);
            allocator.free(self.word_buffer);
            allocator.free(self.block_buffer);

            allocator.free(self.decoder_bf_mat_bin_tmp_buf);
            allocator.free(self.decoder_bf_mat_bin_buf);
            allocator.free(self.decoder_bf_mat_inv_buf);
            allocator.free(self.decoder_bf_sub_mat_buf);

            self.encoder_bf_mat_bin.deinit(allocator);
            self.bf_mat.deinit(allocator);
        }

        pub inline fn exponent(self: Self) Exp {
            return self.bf_mat.field.exp;
        }
        pub inline fn shardCount(self: Self) u8 {
            return self.bf_mat.matrix.numRows();
        }
        pub inline fn shardSize(self: Self) u8 {
            return self.bf_mat.matrix.numCols();
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
            out_fifos_writers: anytype,
        ) !usize {
            var it_enc = self.iterativeEncoder(in_fifo_reader, self.encoder_bf_mat_bin);
            const block = self.block_buffer;
            while (try it_enc.advance(block, out_fifos_writers)) {}
            return it_enc.size;
        }

        pub fn decode(
            self: Self,
            excluded_shards: IndexSet,
            /// `[]const std.io.Reader(...)`
            in_fifos: anytype,
            /// `std.io.Writer(...)`
            out_fifo_writer: anytype,
        ) !usize {
            assert(excluded_shards.count() == (self.shardCount() - self.shardSize()));
            assert(in_fifos.len == self.shardSize());

            const decoder_sub_buf = self.decoder_bf_sub_mat_buf[0..self.bf_mat.subMatrixCellCount(excluded_shards, IndexSet.initEmpty())];
            const decoder_sub = self.bf_mat.subMatrixWith(decoder_sub_buf, excluded_shards, IndexSet.initEmpty());

            const decoder_inv_buf = self.decoder_bf_mat_inv_buf[0..decoder_sub.matrix.getCellCount()];
            const decoder_inv = try decoder_sub.invertWith(decoder_inv_buf);

            const decoder_bin_buf = self.decoder_bf_mat_bin_buf[0..decoder_inv.toBinaryCellCount()];
            const decoder_bin_tmp_buf = self.decoder_bf_mat_bin_tmp_buf[0..decoder_inv.toBinaryTempBufCellCount()];
            const decoder_bin = try decoder_inv.toBinaryWith(decoder_bin_buf, decoder_bin_tmp_buf);

            const PeekStream = std.io.PeekStream(.{ .Static = word_size }, util.PtrSizedReader(@TypeOf(in_fifos[0])));
            const peek_streams = std.mem.bytesAsSlice(PeekStream, self.streams_buffer);
            for (peek_streams, in_fifos) |*stream, *in_fifo| {
                stream.* = std.io.peekStream(word_size, util.ptrSizedReader(in_fifo));
            }

            var size: usize = 0;
            while (true) {
                const block = self.block_buffer;
                const rs = try self.readCodeBlock(block, peek_streams);
                const write_size = try self.writeDataBlock(decoder_bin, block, out_fifo_writer, rs == .done);
                size += write_size;
                switch (rs) {
                    .done => break,
                    .in_progress => continue,
                }
            }

            return size;
        }

        pub fn iterativeEncoder(
            self: *const Self,
            in_fifo_reader: anytype,
            encoder_bin: BinaryFieldMatrix,
        ) IterativeEncoder(@TypeOf(in_fifo_reader)) {
            return .{
                .exp = self.exponent(),
                .shard_count = self.shardCount(),
                .shard_size = self.shardSize(),
                .in_reader = in_fifo_reader,
                .encoder_bin = encoder_bin,
            };
        }

        pub fn IterativeEncoder(comptime InReader: type) type {
            return struct {
                exp: Exp,
                shard_count: u8,
                shard_size: u8,
                in_reader: InReader,
                encoder_bin: BinaryFieldMatrix,
                size: usize = 0,

                /// Returns true if there is still more left to encode,
                /// returns false if everything has been encoded.
                pub fn advance(
                    enc: *@This(),
                    block: []T,
                    /// `[]const std.io.Writer(...)`
                    out_fifo_writers: anytype,
                ) !bool {
                    const rs = try readDataBlock(T, block, enc.in_reader);
                    try writeCodeBlock(T, enc.encoder_bin, block, out_fifo_writers, .{
                        .shard_count = enc.shard_count,
                        .shard_size = enc.shard_size,
                    });
                    switch (rs) {
                        .in_progress => enc.size += calcDataBlockSize(calcChunkSize(word_size, enc.exp), enc.shard_size),
                        .done => {
                            var buffer = [_]u8{0} ** word_size;
                            std.mem.writeIntBig(T, &buffer, block[block.len - 1]);
                            enc.size += buffer[buffer.len - 1];
                        },
                    }
                    return rs == .in_progress;
                }
            };
        }

        pub fn readCodeBlock(
            self: Self,
            /// `[]const std.io.Reader(...)`
            block: []T,
            in_fifos_reader_slice: anytype,
        ) !ReadState {
            @memset(block, 0);

            var buffer = [_]u8{0} ** word_size;

            for (block, 0..block.len) |*block_int, i| {
                const p = i / self.exponent();
                const read_size = try in_fifos_reader_slice[p].reader().readAll(&buffer);
                assert(read_size == buffer.len);
                block_int.* = std.mem.readIntBig(T, &buffer);
            }

            const reader_idx = (block.len - 1) / self.exponent();
            const size: u8 = @intCast(try in_fifos_reader_slice[reader_idx].reader().readAll(&buffer));

            const state: ReadState = if (size == 0) .done else .in_progress;
            if (state != .done) {
                try in_fifos_reader_slice[reader_idx].putBack(&buffer);
            }

            return state;
        }

        pub fn writeDataBlock(
            self: Self,
            decoder: BinaryFieldMatrix,
            code_block: []const T,
            /// `std.io.Writer(...)`
            out_fifo_writer: anytype,
            done: bool,
        ) !usize {
            assert(code_block.len == mulWide(u8, self.exponent(), self.shardSize()));
            const buffer = self.word_buffer;

            for (buffer, 0..mulWide(u8, self.exponent(), self.shardSize())) |*buf, i| {
                var val: T = 0;
                for (0..decoder.numCols()) |j| {
                    if (decoder.get(.{ .row = @intCast(i), .col = @intCast(j) }) == 1) {
                        val ^= code_block[j];
                    }
                }
                std.mem.writeIntBig(T, buf, val);
            }

            const last_word = buffer[buffer.len - 1];
            const data_block_size: u8 = if (done) last_word[last_word.len - 1] else self.dataBlockSize();

            var written_size: usize = 0;
            for (buffer) |*buf| {
                if ((written_size + word_size) <= data_block_size) {
                    try out_fifo_writer.writeAll(buf);
                    written_size += word_size;
                } else {
                    try out_fifo_writer.writeAll(buf[0..(data_block_size - written_size)]);
                    written_size = data_block_size;
                    break;
                }
            }

            return data_block_size;
        }
    };
}

/// Reads a data block, with the full data block size
/// being `block.len * @sizeOf(Word)`.
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
        shard_size: u8,
        shard_count: u8,
    },
) !void {
    const exp: BinaryFiniteField.Exp = @intCast(@divExact(data_block.len, values.shard_size));
    assert(data_block.len == mulWide(u8, exp, values.shard_size));
    var cbw: CodeBlockWriter(Word) = .{
        .exp = exp,
        .shard_count = values.shard_count,
        .encoder = encoder,
        .data_block = data_block,
    };
    while (cbw.next()) |res| {
        try out_fifos[res.index].writeAll(&res.value);
    }
}

pub fn CodeBlockWriter(comptime Word: type) type {
    return struct {
        exp: BinaryFiniteField.Exp,
        shard_count: u8,
        encoder: BinaryFieldMatrix,
        data_block: []const Word,
        index: u8 = 0,
        const Self = @This();

        pub const word_size = roundByteSize(Word);

        pub const NextResult = struct {
            /// The output to write the value to.
            index: u8,
            /// The value to be written to the output. Represents a big endian `T` value.
            value: [word_size]u8,
        };

        pub inline fn next(self: *Self) ?NextResult {
            if (self.index == self.exp * self.shard_count) return null;
            assert(self.index < self.exp * self.shard_count);
            defer self.index += 1;

            var value: Word = 0;

            var j: u8 = 0;
            while (j < self.encoder.numCols()) : (j += 1) {
                if (self.encoder.get(.{ .row = self.index, .col = j }) == 1) {
                    value ^= self.data_block[j];
                }
            }

            return .{
                .index = self.index / self.exp,
                .value = @bitCast(std.mem.nativeToBig(Word, value)),
            };
        }
    };
}

inline fn calcExponent(shard_count: u8, shard_size: u8) error{ShardSizePlusCountOverflow}!BinaryFiniteField.Exp {
    const CountPlusSize = std.math.IntFittingRange(0, std.math.maxInt(u8) * 2);
    const shard_count_plus_size = @as(CountPlusSize, shard_count) + shard_size;
    const ceil_log2 = std.math.log2_int_ceil(CountPlusSize, shard_count_plus_size);

    const Exp = BinaryFiniteField.Exp;
    return std.math.cast(Exp, ceil_log2) orelse
        error.ShardSizePlusCountOverflow;
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
    var set = IndexSet.initEmpty();
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
                for (0..code_filenames.len) |i| {
                    if (excluded_shards.isSet(i)) continue;
                    code_in[j] = try tmp.dir.openFile(code_filenames[i], .{});
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
