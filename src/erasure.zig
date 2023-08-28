const std = @import("std");
const mulWide = std.math.mulWide;
const assert = std.debug.assert;

const BinaryFiniteField = @import("BinaryFiniteField.zig");
const BinaryFieldMatrix = @import("BinaryFieldMatrix.zig");

fn roundByteSize(comptime T: type) comptime_int {
    return @bitSizeOf(T) / @bitSizeOf(u8);
}

pub fn ErasureCoder(comptime T: type) type {
    assert(@typeInfo(T) == .Int);
    return struct {
        encoder: BinaryFieldMatrix,
        shard_count: u8,
        shard_size: u8,
        exp: Exp,

        block_buffer: []T,
        word_buffer: [][word_size]u8,
        const Self = @This();

        const word_size = roundByteSize(T);
        const Exp = BinaryFiniteField.Exp;

        pub const ReadState = enum { done, in_progress };
        pub const ReadOutput = struct {
            block: []T,
            state: ReadState,
        };

        pub fn init(allocator: std.mem.Allocator, shard_count: u8, shard_size: u8) !Self {
            const exp = exp: {
                const CountPlusSize = std.math.IntFittingRange(0, std.math.maxInt(u8) * 2);
                const shard_count_plus_size = @as(CountPlusSize, shard_count) + shard_size;
                break :exp std.math.cast(Exp, std.math.log2_int_ceil(CountPlusSize, shard_count_plus_size)) orelse {
                    return error.ShardSizePlusCountOverflow;
                };
            };

            const bfm = try BinaryFieldMatrix.initCauchy(allocator, shard_count, shard_size, exp);
            errdefer bfm.deinit(allocator);

            const block_buffer = try allocator.alloc(T, mulWide(u8, exp, shard_size));
            errdefer allocator.free(block_buffer);
            @memset(block_buffer, 0);

            const word_buffer = try allocator.alloc([word_size]u8, mulWide(u8, exp, shard_size));
            errdefer allocator.free(word_buffer);
            @memset(word_buffer, .{0} ** word_size);

            return .{
                .encoder = bfm,
                .shard_count = shard_count,
                .shard_size = shard_size,
                .exp = exp,

                .block_buffer = block_buffer,
                .word_buffer = word_buffer,
            };
        }

        pub fn deinit(self: Self, allocator: std.mem.Allocator) void {
            allocator.free(self.word_buffer);
            allocator.free(self.block_buffer);
            self.encoder.deinit(allocator);
        }

        const ChunkSize = std.math.IntFittingRange(0, roundByteSize(T) * std.math.maxInt(Exp));
        pub inline fn chunkSize(self: Self) ChunkSize {
            return @as(ChunkSize, roundByteSize(T)) * self.exp;
        }

        pub inline fn codeBlockSize(self: Self) u8 {
            return self.chunkSize() * self.shard_count;
        }
        pub inline fn dataBlockSize(self: Self) u8 {
            return self.chunkSize() * self.shard_size;
        }

        pub fn readDataBlock(
            self: Self,
            /// `std.io.Reader(...)`
            in_fifo_reader: anytype,
        ) !ReadOutput {
            var block_size: u8 = 0;
            const block = self.block_buffer;
            @memset(block, 0);

            for (block) |*block_int| {
                var buffer = [_]u8{0} ** word_size;
                const read_size = try in_fifo_reader.readAll(&buffer);
                block_size += @intCast(read_size);

                if (read_size < buffer.len) {
                    buffer[buffer.len - 1] = block_size;
                }
                const new_value = std.mem.readIntBig(T, &buffer);
                block_int.* = new_value;

                if (read_size == 0) {
                    // we only end up reading the very last word of the block
                    block[block.len - 1] = new_value;
                    break;
                }
            }

            return ReadOutput{
                .block = block,
                .state = if (block_size < self.dataBlockSize()) .done else .in_progress,
            };
        }

        pub fn readCodeBlock(
            self: Self,
            /// `[]const std.io.Reader(...)`
            in_fifos_reader_slice: anytype,
        ) !ReadOutput {
            const block = self.block_buffer;
            @memset(block, 0);

            var buffer: [word_size]u8 = std.mem.zeroes([word_size]u8);

            for (block, 0..block.len) |*block_int, i| {
                const p = i / self.exp;
                const read_size = try in_fifos_reader_slice[p].reader().readAll(&buffer);
                assert(read_size == buffer.len);
                block_int.* = std.mem.readIntBig(T, &buffer);
            }

            const reader_idx = (block.len - 1) / self.exp;
            const size: u8 = @intCast(try in_fifos_reader_slice[reader_idx].reader().readAll(&buffer));

            const state: ReadState = if (size == 0) .done else .in_progress;
            if (state != .done) {
                try in_fifos_reader_slice[reader_idx].putBack(&buffer);
            }

            return ReadOutput{
                .state = state,
                .block = block,
            };
        }

        pub inline fn codeBlockWriter(self: *const Self, encoder: BinaryFieldMatrix, data_block: []const T) CodeBlockWriter {
            return .{
                .eraser = self,
                .encoder = encoder,
                .data_block = data_block,
            };
        }
        pub const CodeBlockWriter = struct {
            eraser: *const Self,
            encoder: BinaryFieldMatrix,
            data_block: []const T,
            index: u8 = 0,

            pub const NextResult = struct {
                /// The output to write the value to.
                index: u8,
                /// The value to be written to the output. Represents a big endian `T` value.
                value: [word_size]u8,
            };
            pub fn next(self: *CodeBlockWriter) ?NextResult {
                if (self.index == self.eraser.exp * self.eraser.shard_count) return null;
                assert(self.index < self.eraser.exp * self.eraser.shard_count);
                defer self.index += 1;

                var value: T = 0;

                var j: u8 = 0;
                while (j < self.encoder.numCols()) : (j += 1) {
                    if (self.encoder.get(.{ .row = self.index, .col = j }) == 1) {
                        value ^= self.data_block[j];
                    }
                }

                return .{
                    .index = self.index / self.eraser.exp,
                    .value = @bitCast(std.mem.nativeToBig(T, value)),
                };
            }
        };

        pub fn writeCodeBlock(
            self: Self,
            encoder: BinaryFieldMatrix,
            data_block: []const T,
            /// `[]const std.io.Writer(...)`
            out_fifos: anytype,
        ) !void {
            assert(data_block.len == mulWide(u8, self.exp, self.shard_size));
            var cbw = self.codeBlockWriter(encoder, data_block);
            while (cbw.next()) |res| try out_fifos[res.index].writeAll(&res.value);
        }

        pub fn writeDataBlock(
            self: Self,
            decoder: BinaryFieldMatrix,
            code_block: []const T,
            /// `std.io.Writer(...)`
            out_fifo_writer: anytype,
            done: bool,
        ) !usize {
            assert(code_block.len == mulWide(u8, self.exp, self.shard_size));
            const buffer = self.word_buffer;

            for (buffer, 0..mulWide(u8, self.exp, self.shard_size)) |*buf, i| {
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

        pub fn IterativeEncoder(comptime InReader: type) type {
            return struct {
                eraser: *const Self,
                in_reader: InReader,
                encoder_bin: BinaryFieldMatrix,
                size: usize = 0,

                /// Returns true if there is still more left to encode,
                /// returns false if everything has been encoded.
                pub fn advance(
                    enc: *@This(),
                    /// `[]const std.io.Writer(...)`
                    out_fifo_writers: anytype,
                ) !bool {
                    const rs = try enc.eraser.readDataBlock(enc.in_reader);
                    try enc.eraser.writeCodeBlock(enc.encoder_bin, rs.block, out_fifo_writers);
                    switch (rs.state) {
                        .in_progress => {
                            enc.size += enc.eraser.dataBlockSize();
                            return true;
                        },
                        .done => {
                            var buffer = std.mem.zeroes([word_size]u8);
                            std.mem.writeIntBig(T, &buffer, rs.block[rs.block.len - 1]);
                            enc.size += buffer[buffer.len - 1];
                            return false;
                        },
                    }
                }

                pub fn deinit(enc: @This(), allocator: std.mem.Allocator) void {
                    enc.encoder_bin.deinit(allocator);
                }
            };
        }

        pub fn iterativeEncoder(
            self: *const Self,
            allocator: std.mem.Allocator,
            in_fifo_reader: anytype,
        ) !IterativeEncoder(@TypeOf(in_fifo_reader)) {
            return .{
                .eraser = self,
                .in_reader = in_fifo_reader,
                .encoder_bin = try self.encoder.toBinary(allocator),
            };
        }

        pub fn encode(
            self: Self,
            allocator: std.mem.Allocator,
            /// `std.io.Reader(...)`
            in_fifo_reader: anytype,
            /// `[]const std.io.Writer(...)`
            out_fifos_writers: anytype,
        ) !usize {
            var it_enc = try self.iterativeEncoder(allocator, in_fifo_reader);
            defer it_enc.deinit(allocator);
            while (try it_enc.advance(out_fifos_writers)) {}
            return it_enc.size;
        }

        pub fn decode(
            self: Self,
            allocator: std.mem.Allocator,
            excluded_shards: []const u8,
            /// `[]const std.io.Reader(...)`
            in_fifos: anytype,
            /// `std.io.Writer(...)`
            out_fifo_writer: anytype,
        ) !usize {
            assert(excluded_shards.len == (self.shard_count - self.shard_size));
            assert(in_fifos.len == self.shard_size);

            var decoder_sub = try self.encoder.subMatrix(allocator, excluded_shards, &[0]u8{});
            defer decoder_sub.deinit(allocator);

            var decoder_inv = try decoder_sub.invert(allocator);
            defer decoder_inv.deinit(allocator);

            var decoder_bin = try decoder_inv.toBinary(allocator);
            defer decoder_bin.deinit(allocator);

            var size: usize = 0;

            const streams = try allocator.alloc(std.io.PeekStream(.{ .Static = word_size }, std.fs.File.Reader), self.shard_size);
            defer allocator.free(streams);
            // var streams: [self.shard_size]std.io.PeekStream(.{ .Static = word_size }, std.fs.File.Reader) = undefined;
            for (streams, in_fifos) |*stream, in_fifo| stream.* = std.io.peekStream(word_size, in_fifo);

            var done = false;
            while (!done) {
                var rs: ReadOutput = try self.readCodeBlock(streams);
                done = switch (rs.state) {
                    .done => true,
                    .in_progress => false,
                };
                var write_size = try self.writeDataBlock(decoder_bin, rs.block, out_fifo_writer, done);
                size += write_size;
            }
            return size;
        }
    };
}

pub fn sample(
    /// It is advisable to use a Pseudo-RNG here, and not a true RNG,
    /// given the use of `uintLessThan`. See the doc comment on that
    /// function for commentary on the runtime of this function.
    random: std.rand.Random,
    max: u8,
    num: u8,
) std.BoundedArray(u8, std.math.maxInt(u8)) {
    var nums: std.BoundedArray(u8, std.math.maxInt(u8)) = .{};

    while (nums.len < num) {
        const new = random.uintLessThan(u8, max);
        const already_present = std.mem.indexOfScalar(u8, nums.constSlice(), new) != null;
        if (already_present) continue;
        nums.appendAssumeCapacity(new);
    }

    return nums;
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

                break :encode try ec.encode(std.testing.allocator, data_in.reader(), &code_writers);
            };
            try std.testing.expect(data_size > 0);

            decode: {
                const excluded_shards = sample(random, 5, 2);
                // std.log.debug("excluded = {any}\n", .{excluded_shards});

                var code_in: [3]std.fs.File = undefined;
                var code_readers: [3]std.fs.File.Reader = undefined;

                var j: usize = 0;
                for (0..code_filenames.len) |i| {
                    if (std.mem.indexOfScalar(u8, excluded_shards.constSlice(), @intCast(i)) != null) continue;
                    code_in[j] = try tmp.dir.openFile(code_filenames[i], .{});
                    code_readers[j] = code_in[j].reader();
                    j += 1;
                }

                const decoded_filename = "temp_decoded_data_file";

                const decoded_file = try tmp.dir.createFile(decoded_filename, .{});
                defer decoded_file.close();

                const decoded_size = try ec.decode(std.testing.allocator, excluded_shards.constSlice(), &code_readers, decoded_file.writer());
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
