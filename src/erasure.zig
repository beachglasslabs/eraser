const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const galois = @import("erasure/galois.zig");

const std = @import("std");
const assert = std.debug.assert;
const mulWide = std.math.mulWide;

const util = @import("util");

comptime {
    if (@import("builtin").is_test) {
        _ = util;
        _ = galois;
        _ = BinaryFieldMatrix;
    }
}

pub const BinaryFieldMatrix = @import("erasure/BinaryFieldMatrix.zig");
pub const Matrix = @import("erasure/Matrix.zig");
pub const IndexSet = BinaryFieldMatrix.IndexSet;

pub const ReadState = enum { done, in_progress };
pub fn Coder(comptime T: type) type {
    assert(@typeInfo(T) == .Int);
    switch (T) {
        u8, u16, u32 => {},
        else => unreachable,
    }
    return struct {
        bf_mat: BinaryFieldMatrix,
        encoder_bf_mat_bin: BinaryFieldMatrix,

        decoder_bufs_full_allocation: []u8,
        decoder_bufs: DecoderBufs,

        block_buffer: []T,
        const Self = @This();

        pub const word_size = @sizeOf(T);
        const Exp = galois.BinaryField.Exp;

        pub const DecoderBufs = struct {
            sub_mat: []u8,
            mat_inv: []u8,
            mat_bin: []u8,
            mat_bin_tmp: []u8,
        };

        pub const ReadOutput = struct {
            block: []T,
            state: ReadState,
        };

        pub const InitError = std.mem.Allocator.Error || CalcGaloisFieldExponentError || galois.BinaryField.InitError || galois.BinaryField.OpError;
        pub const InitValues = struct { shard_count: u7, shards_required: u7 };
        pub fn init(
            allocator: std.mem.Allocator,
            params: InitValues,
        ) InitError!Self {
            assert(params.shard_count >= params.shards_required);
            const exp = try calcGaloisFieldExponent(params.shard_count, params.shards_required);

            const bf_mat = try BinaryFieldMatrix.initCauchy(allocator, params.shard_count, params.shards_required, exp);
            errdefer bf_mat.deinit(allocator);

            const encoder_bf_mat_bin = try bf_mat.toBinary(allocator);
            errdefer encoder_bf_mat_bin.deinit(allocator);

            const decoder_bufs_result = try util.bbs.fromAlloc(DecoderBufs, allocator, .{
                .sub_mat = bf_mat.matrix.getCellCount(),
                .mat_inv = bf_mat.matrix.getCellCount(),
                .mat_bin = bf_mat.toBinaryCellCount(),
                .mat_bin_tmp = bf_mat.toBinaryTempBufCellCount(),
            });
            const decoder_bufs: DecoderBufs = decoder_bufs_result[0];
            const decoder_buf_full_alloc = decoder_bufs_result[1];
            errdefer allocator.free(decoder_buf_full_alloc);

            const block_buffer = try allocator.alloc(T, mulWide(u8, exp, params.shards_required));
            errdefer allocator.free(block_buffer);

            return .{
                .bf_mat = bf_mat,
                .encoder_bf_mat_bin = encoder_bf_mat_bin,
                .decoder_bufs_full_allocation = decoder_buf_full_alloc,
                .decoder_bufs = decoder_bufs,
                .block_buffer = block_buffer,
            };
        }

        pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
            allocator.free(self.block_buffer);
            allocator.free(self.decoder_bufs_full_allocation);
            self.encoder_bf_mat_bin.deinit(allocator);
            self.bf_mat.deinit(allocator);
        }

        pub inline fn exponent(self: Self) Exp {
            return self.bf_mat.field.exponent();
        }
        pub inline fn shardCount(self: Self) u7 {
            return @intCast(self.bf_mat.matrix.numRows());
        }
        pub inline fn shardsRequired(self: Self) u7 {
            return @intCast(self.bf_mat.matrix.numCols());
        }

        const ChunkSize = std.math.IntFittingRange(0, @sizeOf(T) * std.math.maxInt(Exp));
        pub inline fn chunkSize(self: Self) ChunkSize {
            return calcChunkSize(word_size, self.exponent());
        }

        pub inline fn codeBlockSize(self: Self) u8 {
            return calcCodeBlockSize(self.chunkSize(), self.shardCount());
        }

        pub inline fn dataBlockSize(self: Self) u8 {
            return calcDataBlockSize(self.chunkSize(), self.shardsRequired());
        }

        pub inline fn totalEncodedSize(ec: Self, data_len: u64) u64 {
            const trail_len: u8 = @intCast(data_len % ec.dataBlockSize());
            const padded_len: u64 = data_len - trail_len + ec.dataBlockSize();
            return (padded_len * ec.shardCount()) / ec.shardsRequired();
        }

        pub inline fn encodedSizePerShard(self: Self, data_len: anytype) u64 {
            return self.totalEncodedSize(data_len) / self.shardCount();
        }

        pub inline fn encode(
            self: Self,
            in_fifo_reader: anytype,
            /// `[]const std.io.Writer(...)`
            out_fifo_writers: anytype,
            /// Used to buffer writes to `out_fifos`. Supplying an empty
            /// buffer will cause direct writes to be issued instead.
            write_buffer: []u8,
        ) !usize {
            const Ctx = struct {
                slice: @TypeOf(out_fifo_writers),
                pub inline fn getWriter(ctx: @This(), idx: anytype) @TypeOf(out_fifo_writers[0]) {
                    comptime assert(@TypeOf(idx) == u7);
                    return ctx.slice[idx];
                }
            };
            return self.encodeCtx(in_fifo_reader, Ctx{ .slice = out_fifo_writers }, write_buffer);
        }
        pub fn encodeCtx(
            self: Self,
            /// `std.io.Reader(...)`
            in_fifo_reader: anytype,
            /// Value with an associated namespace, in which a method of the form
            /// `fn getWriter(ctx: @This(), idx: u7) std.io.Writer(...)`
            /// should be defined.
            out_fifos: anytype,
            /// Used to buffer writes to `out_fifos`. Supplying an empty
            /// buffer will cause direct writes to be issued instead.
            write_buffer: []u8,
        ) !usize {
            var size: usize = 0;
            while (true) {
                const data_block = self.block_buffer;
                const rs = try readDataBlock(T, data_block, in_fifo_reader);
                try writeCodeBlock(T, out_fifos, .{
                    .encoder = self.encoder_bf_mat_bin,
                    .data_block = data_block,
                    .shard_count = self.shardCount(),
                    .shards_required = self.shardsRequired(),
                    .write_buffer = write_buffer,
                });
                switch (rs) {
                    .in_progress => size += self.dataBlockSize(),
                    .done => {
                        var buffer = [_]u8{0} ** word_size;
                        std.mem.writeInt(T, &buffer, data_block[data_block.len - 1], .big);
                        size += buffer[buffer.len - 1];
                        break;
                    },
                }
            }
            return size;
        }
        /// Encode only a single shard, discarding the rest of
        /// the corresponding data acquired from `reader`.
        pub fn encodeOneShard(
            self: Self,
            /// `std.io.Reader(...)`
            reader: anytype,
            /// Which shard to encode
            writer_idx: u7,
            /// `std.io.Writer(...)`
            writer: anytype,
        ) !void {
            const exp: galois.BinaryField.Exp = calcGaloisFieldExponent(self.shardCount(), self.shardsRequired()) catch unreachable;
            while (true) {
                const data_block = self.block_buffer;
                const rs = try readDataBlock(T, data_block, reader);
                try writeCodeBlockShard(T, writer, .{
                    .exp = exp,
                    .writer_idx = writer_idx,
                    .encoder = self.encoder_bf_mat_bin,
                    .data_block = data_block,
                });
                switch (rs) {
                    .in_progress => {},
                    .done => break,
                }
            }
        }

        pub inline fn decode(
            self: Self,
            excluded_shards: IndexSet,
            /// `std.io.Writer(...)`
            out_fifo_writer: anytype,
            /// `[]const std.io.Reader(...)`
            in_fifos: anytype,
        ) !usize {
            assert(in_fifos.len == self.shardsRequired());
            const Ctx = struct {
                slice: @TypeOf(in_fifos),
                pub inline fn getReader(ctx: @This(), idx: anytype) @TypeOf(in_fifos[0]) {
                    comptime assert(@TypeOf(idx) == u7);
                    return ctx.slice[idx];
                }
            };
            return self.decodeCtx(excluded_shards, out_fifo_writer, Ctx{ .slice = in_fifos });
        }
        pub fn decodeCtx(
            self: Self,
            excluded_shards: IndexSet,
            /// `std.io.Writer(...)`
            out_fifo_writer: anytype,
            /// Value with an associated namespace, in which a method of the form
            /// `fn getReader(ctx: @This(), idx: u7) std.io.Reader(...)`
            /// should be defined.
            in_fifos_ctx: anytype,
        ) !usize {
            assert(excluded_shards.count() == self.shardCount() - self.shardsRequired());

            const decoder_bin = blk: {
                const decoder_sub_buf = self.decoder_bufs.sub_mat[0..self.bf_mat.subMatrixCellCount(excluded_shards, IndexSet{})];
                const decoder_sub = self.bf_mat.subMatrixWith(decoder_sub_buf, excluded_shards, IndexSet{});

                const decoder_inv_buf = self.decoder_bufs.mat_inv[0..decoder_sub.matrix.getCellCount()];
                const decoder_inv = try decoder_sub.invertWith(decoder_inv_buf);

                const decoder_bin_buf = self.decoder_bufs.mat_bin[0..decoder_inv.toBinaryCellCount()];
                const decoder_bin_tmp_buf = self.decoder_bufs.mat_bin_tmp[0..decoder_inv.toBinaryTempBufCellCount()];

                break :blk try decoder_inv.toBinaryWith(decoder_bin_buf, decoder_bin_tmp_buf);
            };

            var tail_bytes: ?[word_size]u8 = null;
            var size: usize = 0;
            while (true) {
                const block = self.block_buffer;
                tail_bytes = try readCodeBlock(T, self.exponent(), block, in_fifos_ctx, tail_bytes);
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

        pub inline fn sampleExcludedIndexSet(self: Self, random: std.rand.Random) IndexSet {
            return sampleIndexSet(
                random,
                self.shardCount(),
                self.shardCount() - self.shardsRequired(),
            );
        }
    };
}

/// Reads a data block, with the full data block size
/// being `block.len * roundByteSize(Word)`.
pub fn readDataBlock(
    comptime Word: type,
    block_buffer: []Word,
    /// `std.io.Reader(...)`
    data_reader: anytype,
) @TypeOf(data_reader).Error!ReadState {
    const word_size = @sizeOf(Word);
    @memset(block_buffer, 0);
    const data_block_size = block_buffer.len * word_size;
    const block_buffer_bytes = std.mem.sliceAsBytes(block_buffer);
    assert(block_buffer_bytes.len == data_block_size);

    const block_size: u8 = @intCast(try data_reader.readAll(block_buffer_bytes));
    @memset(block_buffer_bytes[block_size..], block_size);

    switch (native_endian) {
        .big => {},
        .little => if (comptime word_size > 1) {
            for (block_buffer) |*word| word.* = @byteSwap(word.*);
        },
    }

    if (block_size < block_buffer_bytes.len)
        return .done;
    return .in_progress;
}

pub fn writeCodeBlock(
    comptime Word: type,
    /// Value with an associated namespace, in which a method of the form
    /// `fn getWriter(ctx: @This(), idx: u7) std.io.Writer(...)`
    /// should be defined.
    out_fifos: anytype,
    values: struct {
        encoder: BinaryFieldMatrix,
        data_block: []const Word,
        shard_count: u7,
        shards_required: u7,
        write_buffer: []u8,
    },
) !void {
    const exp: galois.BinaryField.Exp = calcGaloisFieldExponent(values.shard_count, values.shards_required) catch unreachable;
    assert(@divExact(values.data_block.len, values.shards_required) == exp);

    for (0..values.shard_count) |writer_idx_uncasted| {
        const writer_idx: u7 = @intCast(writer_idx_uncasted);
        const current_writer = out_fifos.getWriter(writer_idx);
        var buffered = util.sliceBufferedWriter(current_writer, values.write_buffer);
        try writeCodeBlockShard(Word, buffered.writer(), .{
            .exp = exp,
            .writer_idx = writer_idx,
            .encoder = values.encoder.matrix,
            .data_block = values.data_block,
        });
        try buffered.flush();
    }
}

pub fn writeCodeBlockShard(
    comptime Word: type,
    writer: anytype,
    values: struct {
        exp: galois.BinaryField.Exp,
        writer_idx: u7,
        encoder: Matrix,
        data_block: []const Word,
    },
) !void {
    const exp = values.exp;
    const writer_idx = values.writer_idx;
    const encoder = values.encoder;

    for (writer_idx * exp..(writer_idx + 1) * exp) |row_uncasted| {
        const row: u8 = @intCast(row_uncasted);

        var value: Word = 0;
        for (encoder.getRow(row), 0..encoder.numCols()) |col_val, col_idx_uncasted| {
            const col_idx: u8 = @intCast(col_idx_uncasted);
            assert(col_val == 0 or col_val == 1);
            value ^= values.data_block[col_idx] * col_val;
        }

        const word_size = @sizeOf(Word);
        const word: [word_size]u8 = @bitCast(std.mem.nativeToBig(Word, value));
        try writer.writeAll(&word);
    }
}

/// Returns null if reading is finished.
/// Otherwise returns the last bytes read from the reader at index `(block.len - 1) / exp`.
/// These returned bytes should be passed as the `last_bytes_from_prev_call` parameter on a subsequent call.
pub fn readCodeBlock(
    comptime Word: type,
    exp: galois.BinaryField.Exp,
    block: []Word,
    /// Value with an associated namespace, in which a method of the form
    /// `fn getReader(ctx: @This(), idx: u7) std.io.Reader(...)`
    /// should be defined.
    readers_ctx: anytype,
    /// `null` if this is the first call, otherwise
    /// this should be the result from the previous call to this function.
    last_bytes_from_prev_call: ?[@sizeOf(Word)]u8,
) !?[@sizeOf(Word)]u8 {
    @memset(block, 0);
    const word_size = @sizeOf(Word);

    var maybe_last_reader_bytes = last_bytes_from_prev_call;
    const last_reader_idx: u7 = @intCast((block.len - 1) / exp);

    for (block, 0..) |*block_int, i| {
        var buffer = [_]u8{0} ** word_size;
        const reader_idx: u7 = @intCast(i / exp);

        const use_prev_bytes =
            reader_idx == last_reader_idx and
            maybe_last_reader_bytes != null //
        ;

        if (use_prev_bytes) {
            buffer = maybe_last_reader_bytes.?;
            maybe_last_reader_bytes = null;
        } else {
            const read_size = try readers_ctx.getReader(reader_idx).readAll(&buffer);
            if (read_size < buffer.len) return error.EndOfStream;
            assert(read_size == buffer.len);
        }

        block_int.* = std.mem.readInt(Word, &buffer, .big);
    }

    var buffer = [_]u8{0} ** word_size;
    const size = try readers_ctx.getReader(last_reader_idx).readAll(&buffer);

    return switch (size) {
        0 => null,
        word_size => buffer,
        else => error.EndOfStream,
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
    const word_size = @sizeOf(T);
    const full_data_block_size: u8 = @intCast(params.code_block.len * word_size);

    const data_block_size: u8 = if (!params.done) full_data_block_size else blk: {
        const i: u8 = @intCast(params.code_block.len - 1);

        var val: T = 0;
        for (params.code_block, 0..params.decoder.numCols()) |code_byte, j| {
            const idx: Matrix.CellIndex = .{ .row = i, .col = @intCast(j) };
            if (params.decoder.get(idx) == 1) {
                val ^= code_byte;
            }
        }

        var buf = [_]u8{0} ** word_size;
        std.mem.writeInt(T, &buf, val, .big);
        break :blk buf[buf.len - 1];
    };

    var written_size: usize = 0;
    for (0..params.code_block.len) |i| {
        var val: T = 0;
        for (params.code_block, 0..params.decoder.numCols()) |code_byte, col| {
            const idx: Matrix.CellIndex = .{ .row = @intCast(i), .col = @intCast(col) };
            if (params.decoder.get(idx) == 1) val ^= code_byte;
        }

        var word = [_]u8{0} ** word_size;
        std.mem.writeInt(T, &word, val, .big);

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

pub const CalcGaloisFieldExponentError = error{ ShardSizePlusCountOverflow, ZeroShards, ZeroShardSize };
pub inline fn calcGaloisFieldExponent(shard_count: u7, shards_required: u7) CalcGaloisFieldExponentError!galois.BinaryField.Exp {
    if (shard_count == 0) return error.ZeroShards;
    if (shards_required == 0) return error.ZeroShardSize;

    const count_plus_size = @as(u8, shard_count) + shards_required;
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
    return @as(u8, chunk_size) * shard_count;
}
inline fn calcDataBlockSize(
    /// Size of each chunk, likely calculated using `calcChunkSize`.
    chunk_size: anytype,
    shards_required: u7,
) u8 {
    return @as(u8, chunk_size) * shards_required;
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

test Coder {
    const test_data = [_][]const u8{
        "The quick brown fox jumps over the lazy dog.",
        "All your base are belong to us.",
        "All work and no play makes Jack a dull boy.",
        "Whoever fights monsters should see to it that in the process he does not become a monster.\nAnd if you gaze long enough into an abyss, the abyss will gaze back into you.\n",
        comptime rand: {
            var prng = std.rand.Sfc64.init(4312);
            const random = prng.random();
            var bytes: [2048]u8 = undefined;
            @setEvalBranchQuota(bytes.len * 10);
            random.bytes(&bytes);
            break :rand &bytes;
        },
    };

    var prng = std.rand.DefaultPrng.init(0xdeadbeef);
    const random = prng.random();

    for (test_data) |data| {
        inline for ([_]type{ u8, u16, u32 }) |T| {
            for ([_]Coder(T).InitValues{
                .{ .shard_count = 6, .shards_required = 3 },
                .{ .shard_count = 5, .shards_required = 3 },
                .{ .shard_count = 4, .shards_required = 3 },
                .{ .shard_count = 4, .shards_required = 2 },
                .{ .shard_count = 12, .shards_required = 8 },
                .{ .shard_count = 12, .shards_required = 2 },
            }) |distribution| {
                errdefer std.log.err("Failed with T={}, {}, data='{s}'", .{ T, distribution, data });

                const ec = try Coder(T).init(std.testing.allocator, distribution);
                defer ec.deinit(std.testing.allocator);

                const code_datas = try std.testing.allocator.alloc(std.ArrayListUnmanaged(u8), ec.shardCount());
                @memset(code_datas, .{});
                defer {
                    for (code_datas) |*code| code.deinit(std.testing.allocator);
                    std.testing.allocator.free(code_datas);
                }

                const actual_encoded_size: usize = encode: {
                    const WritersCtx = struct {
                        allocator: std.mem.Allocator,
                        code_datas: []std.ArrayListUnmanaged(u8),

                        pub inline fn getWriter(ctx: @This(), idx: u7) std.ArrayListUnmanaged(u8).Writer {
                            return ctx.code_datas[idx].writer(ctx.allocator);
                        }
                    };
                    var data_in = std.io.fixedBufferStream(data);
                    const writers = WritersCtx{
                        .allocator = std.testing.allocator,
                        .code_datas = code_datas,
                    };
                    const actual_encoded_size = try ec.encodeCtx(data_in.reader(), writers, &.{});

                    const expected_total_encoded_size = ec.totalEncodedSize(data.len);
                    var actual_total_encoded_size: u64 = 0;
                    for (writers.code_datas) |code| {
                        actual_total_encoded_size += code.items.len;
                        try std.testing.expectEqual(ec.encodedSizePerShard(data.len), code.items.len);
                    }

                    try std.testing.expectEqual(expected_total_encoded_size, actual_total_encoded_size);

                    break :encode actual_encoded_size;
                };
                try std.testing.expectEqual(data.len, actual_encoded_size);

                decode: {
                    const excluded_shards = sampleIndexSet(
                        random,
                        ec.shardCount(),
                        ec.shardCount() - ec.shardsRequired(),
                    );

                    const ReadersCtx = struct {
                        excluded_shards: IndexSet,
                        code_datas: []std.ArrayListUnmanaged(u8),

                        pub inline fn getReader(ctx: @This(), idx: u7) Reader {
                            const abs_idx = ctx.excluded_shards.absoluteFromExclusiveSubIndex(idx);
                            return .{ .context = &ctx.code_datas[abs_idx] };
                        }

                        const Reader = std.io.Reader(*std.ArrayListUnmanaged(u8), error{}, @This().read);
                        fn read(list: *std.ArrayListUnmanaged(u8), buf: []u8) error{}!usize {
                            const amt = @min(list.items.len, buf.len);
                            @memcpy(buf[0..amt], list.items[0..amt]);
                            std.mem.copyForwards(u8, list.items, list.items[amt..]);
                            list.shrinkRetainingCapacity(list.items.len - amt);
                            return amt;
                        }
                    };
                    const readers_ctx = ReadersCtx{
                        .excluded_shards = excluded_shards,
                        .code_datas = code_datas,
                    };

                    var decoded_data = std.ArrayList(u8).init(std.testing.allocator);
                    defer decoded_data.deinit();

                    const decoded_size = try ec.decodeCtx(excluded_shards, decoded_data.writer(), readers_ctx);
                    try std.testing.expectEqual(actual_encoded_size, decoded_size);
                    try std.testing.expectEqual(decoded_size, decoded_data.items.len);

                    try std.testing.expectEqualStrings(data, decoded_data.items);
                    break :decode;
                }
            }
        }
    }
}
