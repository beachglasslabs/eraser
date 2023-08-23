const std = @import("std");
const mulWide = std.math.mulWide;
const assert = std.debug.assert;

const BinaryFiniteField = @import("BinaryFiniteField.zig");
const BinaryFieldMatrix = @import("BinaryFieldMatrix.zig");

inline fn roundByteSize(comptime T: type) usize {
    comptime return @bitSizeOf(T) / @bitSizeOf(u8);
}

pub fn ErasureCoder(comptime T: type) type {
    assert(@typeInfo(T) == .Int);
    return struct {
        encoder: BinaryFieldMatrix,
        chunk_size: usize,
        shard_count: u8,
        shard_size: u8,
        exp: std.math.Log2IntCeil(u8),

        block_buffer: []T,
        word_buffer: [][word_size]u8,
        const Self = @This();

        const word_size = roundByteSize(T);

        pub const ReadState = enum { done, in_progress };
        pub const ReadOutput = struct {
            block: []T,
            size: u8,
            state: ReadState,
        };

        pub fn init(allocator: std.mem.Allocator, shard_count: u8, shard_size: u8) !Self {
            const exp: BinaryFiniteField.Exp = @intCast(std.math.log2_int_ceil(u8, shard_count + shard_size)); // <- TODO: handle overflow of n + k?
            const chunk_size = roundByteSize(T) * exp;

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
                .chunk_size = chunk_size,
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

        pub inline fn codeBlockSize(self: Self) usize {
            return self.chunk_size * self.shard_count;
        }
        pub inline fn dataBlockSize(self: Self) usize {
            return self.chunk_size * self.shard_size;
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
                block_int.* = std.mem.readIntBig(T, &buffer);
            }

            return ReadOutput{
                .block = block,
                .size = block_size,
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
                .size = size,
                .block = block,
            };
        }

        pub fn writeCodeBlock(
            self: Self,
            encoder: BinaryFieldMatrix,
            data_block: []const T,
            /// `[]const std.io.Writer(...)`
            out_fifos: anytype,
        ) !void {
            assert(data_block.len == mulWide(u8, self.exp, self.shard_size));

            for (0..mulWide(u8, self.exp, self.shard_count)) |i| {
                var val: T = 0;
                for (0..encoder.numCols()) |j| {
                    if (encoder.get(.{ .row = @intCast(i), .col = @intCast(j) }) == 1) {
                        val ^= data_block[j];
                    }
                }
                try out_fifos[i / self.exp].writeIntBig(T, val);
            }
        }

        pub fn writeDataBlock(
            self: Self,
            decoder: BinaryFieldMatrix,
            code_block: []const T,
            out_fifo: std.fs.File.Writer,
            done: bool,
        ) !usize {
            assert(code_block.len == mulWide(u8, self.exp, self.shard_size));

            const buffer = self.word_buffer;

            for (0..mulWide(u8, self.exp, self.shard_size)) |i| {
                var val: T = 0;
                for (0..decoder.numCols()) |j| {
                    if (decoder.get(.{ .row = @intCast(i), .col = @intCast(j) }) == 1) {
                        val ^= code_block[j];
                    }
                }
                std.mem.writeIntBig(T, &buffer[i], val);
            }

            var data_block_size: usize = 0;

            if (done) {
                data_block_size = buffer[buffer.len - 1][buffer[0].len - 1];
            } else {
                data_block_size = self.dataBlockSize();
            }

            var written_size: usize = 0;
            for (buffer) |b| {
                if ((written_size + word_size) <= data_block_size) {
                    try out_fifo.writeAll(&b);
                    written_size += word_size;
                } else {
                    try out_fifo.writeAll(b[0..(data_block_size - written_size)]);
                    written_size = data_block_size;
                    break;
                }
            }
            return data_block_size;
        }

        pub fn encode(
            self: Self,
            allocator: std.mem.Allocator,
            /// `std.io.Reader(...)`
            in_fifo_reader: anytype,
            /// `[]const std.io.Writer(...)`
            out_fifos_writers: anytype,
        ) !usize {
            assert(out_fifos_writers.len == self.shard_count);

            var encoder_bin = try self.encoder.toBinary(allocator);
            defer encoder_bin.deinit(allocator);

            var size: usize = 0;
            while (true) {
                const rs = try self.readDataBlock(in_fifo_reader);

                try self.writeCodeBlock(encoder_bin, rs.block, out_fifos_writers);
                switch (rs.state) {
                    .in_progress => size += self.dataBlockSize(),
                    .done => {
                        var buffer = std.mem.zeroes([word_size]u8);
                        std.mem.writeIntBig(T, &buffer, rs.block[rs.block.len - 1]);
                        size += buffer[buffer.len - 1];
                        break;
                    },
                }
            }

            return size;
        }

        pub fn decode(
            self: Self,
            allocator: std.mem.Allocator,
            excluded_shards: []const u8,
            in_fifos: []const std.fs.File.Reader,
            /// `std.io.Writer(...)`
            out_fifo_writer: anytype,
        ) !usize {
            assert(excluded_shards.len == (self.shard_count - self.shard_size));
            assert(in_fifos.len == self.shard_size);

            var decoder_sub = try self.encoder.subMatrix(allocator, self.shard_count - self.shard_size, 0, excluded_shards, &[0]u8{});
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
