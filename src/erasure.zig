const builtin = @import("builtin");
const native_endian = builtin.cpu.arch.endian();

const galois = @import("erasure/galois.zig");

const std = @import("std");
const assert = std.debug.assert;
const mulWide = std.math.mulWide;

const util = @import("util.zig");

comptime {
    if (@import("builtin").is_test) {
        _ = util;
        _ = galois;
        _ = BinaryFieldMatrix;
    }
}

pub const BinaryFieldMatrix = @import("erasure/BinaryFieldMatrix.zig");
pub const IndexSet = BinaryFieldMatrix.IndexSet;

pub fn roundByteSize(comptime T: type) comptime_int {
    const result = @bitSizeOf(T) / @bitSizeOf(u8);
    assert(result == @sizeOf(T));
    return result;
}

pub const ReadState = enum { done, in_progress };
pub fn Coder(comptime T: type) type {
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

        pub const InitError = std.mem.Allocator.Error || CalcGaloisFieldExponentError || galois.BinaryField.InitError || galois.BinaryField.OpError;
        pub const InitValues = struct {
            shard_count: u7,
            shards_required: u7,
        };
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

            assert( //
                decoder_buf_fba_state.end_index ==
                decoder_buf_fba_state.buffer.len);

            const block_buffer = try allocator.alloc(T, mulWide(u8, exp, params.shards_required));
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
        pub inline fn shardsRequired(self: Self) u7 {
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
            return calcDataBlockSize(self.chunkSize(), self.shardsRequired());
        }

        pub inline fn encode(
            self: Self,
            in_fifo_reader: anytype,
            /// `[]const std.io.Writer(...)`
            out_fifo_writers: anytype,
        ) !usize {
            const Ctx = struct {
                slice: @TypeOf(out_fifo_writers),
                pub inline fn getWriter(ctx: @This(), idx: anytype) @TypeOf(out_fifo_writers[0]) {
                    comptime assert(@TypeOf(idx) == u7);
                    return ctx.slice[idx];
                }
            };
            return self.encodeCtx(in_fifo_reader, Ctx{ .slice = out_fifo_writers });
        }
        pub fn encodeCtx(
            self: Self,
            /// `std.io.Reader(...)`
            in_fifo_reader: anytype,
            /// Value with an associated namespace, in which a method of the form
            /// `fn getWriter(ctx: @This(), idx: u7) std.io.Writer(...)`
            /// should be defined.
            out_fifo_writers_ctx: anytype,
        ) !usize {
            var size: usize = 0;
            while (true) {
                const data_block = self.block_buffer;
                const rs = try readDataBlock(T, data_block, in_fifo_reader);
                try writeCodeBlock(T, self.encoder_bf_mat_bin, data_block, out_fifo_writers_ctx, .{
                    .shard_count = self.shardCount(),
                    .shards_required = self.shardsRequired(),
                });
                switch (rs) {
                    .in_progress => size += calcDataBlockSize(calcChunkSize(word_size, self.exponent()), self.shardsRequired()),
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
    block: []Word,
    /// `std.io.Reader(...)`
    data_reader: anytype,
) @TypeOf(data_reader).Error!ReadState {
    const word_size = roundByteSize(Word);
    @memset(block, 0);
    const data_block_size = block.len * word_size;
    var block_size: u8 = 0;

    if (word_size == 1) {} else {}
    for (block) |*block_int| {
        var buffer: [word_size]u8 = undefined;
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
    /// Value with an associated namespace, in which a method of the form
    /// `fn getWriter(ctx: @This(), idx: u7) std.io.Writer(...)`
    /// should be defined.
    out_fifos: anytype,
    values: struct {
        shard_count: u7,
        shards_required: u7,
    },
) !void {
    const exp: galois.BinaryField.Exp = calcGaloisFieldExponent(values.shard_count, values.shards_required) catch unreachable;
    assert(@divExact(data_block.len, values.shards_required) == exp);

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
        try out_fifos.getWriter(out_idx).writeAll(&word);
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
    last_bytes_from_prev_call: ?[roundByteSize(Word)]u8,
) !?[roundByteSize(Word)]u8 {
    @memset(block, 0);
    const word_size = roundByteSize(Word);

    var maybe_last_reader_bytes = last_bytes_from_prev_call;
    const last_reader_idx: u7 = @intCast((block.len - 1) / exp);

    for (block, 0..) |*block_int, i| {
        var buffer = [_]u8{0} ** word_size;
        const reader_idx: u7 = @intCast(i / exp);

        const use_prev_bytes =
            reader_idx == last_reader_idx and
            maybe_last_reader_bytes != null;
        if (use_prev_bytes) {
            buffer = maybe_last_reader_bytes.?;
            maybe_last_reader_bytes = null;
        } else {
            const read_size = try readers_ctx.getReader(reader_idx).readAll(&buffer);
            if (read_size < buffer.len) return error.EndOfStream;
            assert(read_size == buffer.len);
        }

        block_int.* = std.mem.readIntBig(Word, &buffer);
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
    return chunk_size * shard_count;
}
inline fn calcDataBlockSize(
    /// Size of each chunk, likely calculated using `calcChunkSize`.
    chunk_size: anytype,
    shards_required: u8,
) u8 {
    return chunk_size * shards_required;
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
        "Whoever fights monsters should see to it that in the process he does not become a monster.\nAnd if you gaze long enough into an abyss, the abyss will gaze back into you.",
    };

    var prng = std.rand.DefaultPrng.init(1234);
    var random = prng.random();

    for (test_data) |data| {
        inline for ([_]type{ u8, u16, u32, u64 }) |T| {
            var ec = try Coder(T).init(std.testing.allocator, .{
                .shard_count = 5,
                .shards_required = 3,
            });
            defer ec.deinit(std.testing.allocator);

            const code_datas = try std.testing.allocator.alloc(std.ArrayListUnmanaged(u8), ec.shardCount());
            @memset(code_datas, .{});
            defer {
                for (code_datas) |*code| code.deinit(std.testing.allocator);
                std.testing.allocator.free(code_datas);
            }

            const data_size: usize = encode: {
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
                break :encode try ec.encodeCtx(data_in.reader(), writers);
            };
            try std.testing.expect(data_size > 0);

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
                try std.testing.expectEqual(data_size, decoded_size);
                try std.testing.expectEqual(decoded_size, decoded_data.items.len);

                try std.testing.expectEqualStrings(data, decoded_data.items);
                break :decode;
            }
        }
    }
}
