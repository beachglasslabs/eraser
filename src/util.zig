const std = @import("std");
const assert = std.debug.assert;

pub inline fn srcFmt(src: std.builtin.SourceLocation) SrcFmt {
    return .{ .src = src };
}
pub const SrcFmt = struct {
    src: std.builtin.SourceLocation,
    pub fn format(
        self: SrcFmt,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        const mention_fn = comptime std.mem.indexOfScalar(u8, fmt_str, 'f') != null;
        _ = options;
        try writer.print("{s}:{d}:{d}", .{ self.src.file, self.src.line, self.src.column });
        if (mention_fn) try writer.print(" ({s})", .{self.src.fn_name});
    }
};

pub inline fn initNoDefault(
    comptime T: type,
    full_init: FullInit: {
        const info = switch (@typeInfo(T)) {
            .Struct => |info| info,
            else => break :FullInit T,
        };

        var new_fields: [info.fields.len]std.builtin.Type.StructField = info.fields[0..].*;
        @setEvalBranchQuota(new_fields.len + 100);
        inline for (&new_fields) |*field| {
            if (field.is_comptime) continue;
            field.default_value = null;
        }

        var new_info = info;
        new_info.fields = &new_fields;
        new_info.decls = &.{};
        break :FullInit @Type(.{ .Struct = new_info });
    },
) T {
    const fields = switch (@typeInfo(T)) {
        .Struct => |info| info.fields,
        inline else => |_, tag| @compileError(
            "Expected struct, got " ++ @typeName(T) ++ "', which is a '" ++ @tagName(tag) ++ "'",
        ),
    };

    var result: T = undefined;
    @setEvalBranchQuota(fields.len + 100);
    inline for (fields) |field| {
        @field(result, field.name) = @field(full_init, field.name);
    }
    return result;
}

pub inline fn sliceBufferedWriter(inner: anytype, buf: []u8) SliceBufferedWriter(@TypeOf(inner)) {
    return .{ .inner = inner, .buf = buf };
}
pub fn SliceBufferedWriter(comptime Inner: type) type {
    return struct {
        inner: Inner,
        buf: []u8,
        end: usize = 0,
        const Self = @This();

        const Error = Inner.Error;
        pub const Writer = std.io.Writer(*Self, Self.Error, Self.write);

        pub inline fn writer(self: *Self) Writer {
            return .{ .context = self };
        }

        pub inline fn flush(self: *Self) !void {
            try self.inner.writeAll(self.buf[0..self.end]);
            self.end = 0;
        }

        fn write(self: *Self, bytes: []const u8) Error!usize {
            if (self.end + bytes.len > self.buf.len) {
                try self.flush();
                if (bytes.len > self.buf.len)
                    return self.inner.write(bytes);
            }

            const new_end = self.end + bytes.len;
            @memcpy(self.buf[self.end..new_end], bytes);
            self.end = new_end;
            return bytes.len;
        }
    };
}

pub inline fn hardCodeFmt(
    comptime fmt_str: []const u8,
    value: anytype,
) HardCodeFmt(fmt_str, @TypeOf(value)) {
    return .{ .value = value };
}
pub fn HardCodeFmt(comptime fmt_str: []const u8, comptime T: type) type {
    return struct {
        value: T,
        const Self = @This();

        pub fn format(
            self: Self,
            comptime alt_fmt_str: []const u8,
            options: std.fmt.FormatOptions,
            writer: anytype,
        ) @TypeOf(writer).Error!void {
            _ = alt_fmt_str;
            try std.fmt.formatType(self.value, fmt_str, options, writer, std.fmt.default_max_depth);
        }
    };
}

pub inline fn lowerCaseFmt(string: []const u8) LowerCaseFmt {
    return .{ .string = string };
}
pub const LowerCaseFmt = struct {
    string: []const u8,

    pub fn format(
        self: LowerCaseFmt,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        _ = fmt_str;
        try writeLowerCaseString(writer, self.string);
    }
};

pub fn writeLowerCaseString(writer: anytype, bytes: []const u8) @TypeOf(writer).Error!void {
    if (bytes.len == 0) return;

    var i: usize = 0;
    if (comptime std.simd.suggestVectorSize(u8)) |vec_len| {
        while (i + vec_len <= bytes.len) : (i += vec_len) {
            const Vec = @Vector(vec_len, u8);
            var vec: Vec = bytes[i..][0..vec_len].*;

            var uppers: @Vector(vec_len, u1) = .{1} ** vec_len;
            uppers &= @bitCast(vec >= @as(Vec, @splat('A')));
            uppers &= @bitCast(vec <= @as(Vec, @splat('Z')));

            vec = @select(u8, @as(@Vector(vec_len, bool), @bitCast(uppers)), vec | @as(Vec, @splat(0b00100000)), vec);
            try writer.writeAll(&@as([vec_len]u8, vec));
        }
    }

    for (bytes[i..]) |c| {
        try writer.writeByte(std.ascii.toLower(c));
    }
}

pub inline fn pumpReaderToWriterThroughFifo(
    src_reader: anytype,
    dest_writer: anytype,
    comptime pump_type: enum { static, slice },
    pump_buf: switch (pump_type) {
        .static => comptime_int,
        .slice => []u8,
    },
) !void {
    const Fifo = std.fifo.LinearFifo(u8, switch (pump_type) {
        .static => .{ .Static = pump_buf },
        .slice => .Slice,
    });
    var fifo = switch (pump_type) {
        .static => Fifo.init(),
        .slice => Fifo.init(pump_buf),
    };
    try fifo.pump(src_reader, dest_writer);
}

comptime {
    _ = buffer_backed_slices;
}
pub const buffer_backed_slices = struct {
    pub fn SliceLengths(comptime S: type) type {
        return Impl(S).Lengths;
    }
    pub fn bufferAlignment(comptime S: type) comptime_int {
        return Impl(S).max_align;
    }
    pub fn bufferLength(comptime S: type, lengths: Impl(S).Lengths) usize {
        return Impl(S).calcBufferOffsetsAndSize(lengths)[1];
    }

    pub inline fn fromBuffer(
        comptime S: type,
        buf: []align(bufferAlignment(S)) u8,
        lengths: SliceLengths(S),
    ) S {
        const I = Impl(S);
        const offsets, const buffer_size = I.calcBufferOffsetsAndSize(lengths);
        assert(buf.len == buffer_size);
        return I.fromBufferImpl(buf, lengths, offsets);
    }

    /// Appends the backing buffer to the array list, and returns the buffer struct.
    pub inline fn fromArrayList(
        comptime S: type,
        array_list: *std.ArrayListAligned(u8, bufferAlignment(S)),
        lengths: SliceLengths(S),
    ) std.mem.Allocator.Error!S {
        const I = Impl(S);
        const offsets, const buffer_size = I.calcBufferOffsetsAndSize(lengths);
        try array_list.resize(buffer_size);
        return I.fromBufferImpl(array_list.items, lengths, offsets);
    }

    pub inline fn fromAlloc(
        comptime S: type,
        allocator: std.mem.Allocator,
        lengths: SliceLengths(S),
    ) std.mem.Allocator.Error!struct { S, []align(bufferAlignment(S)) u8 } {
        const I = Impl(S);

        const offsets, const buffer_size = I.calcBufferOffsetsAndSize(lengths);

        const alloc = try allocator.alignedAlloc(u8, I.max_align, buffer_size);
        errdefer allocator.free(alloc);

        const result = I.fromBufferImpl(alloc, lengths, offsets);
        return .{ result, alloc };
    }

    fn Impl(comptime S: type) type {
        return struct {
            /// Returns the offsets struct and the exact required buffer length.
            inline fn calcBufferOffsetsAndSize(lengths: Lengths) struct { Offsets, usize } {
                var offsets: Offsets = undefined;

                var offset: usize = 0;
                inline for (ordered_ids) |id| {
                    const field_info = fields[@intFromEnum(id)];
                    const pointer = @typeInfo(field_info.type).Pointer;
                    offset = std.mem.alignForward(usize, offset, pointer.alignment);
                    @field(offsets, field_info.name) = offset;
                    offset += @sizeOf(pointer.child) * @field(lengths, field_info.name);
                }

                return .{ offsets, offset };
            }

            fn fromBufferImpl(
                /// asserts `buf.len == bufferLength(S, lengths)`
                buf: []align(bufferAlignment(S)) u8,
                lengths: SliceLengths(S),
                offsets: Offsets,
            ) S {
                var result: S = undefined;
                inline for (Impl(S).fields) |field| {
                    const pointer = @typeInfo(field.type).Pointer;
                    const offset = @field(offsets, field.name);
                    const byte_len = @field(lengths, field.name) * @sizeOf(pointer.child);
                    @field(result, field.name) = @alignCast(switch (pointer.size) {
                        .Slice => std.mem.bytesAsSlice(pointer.child, buf[offset..][0..byte_len]),
                        .Many => std.mem.bytesAsSlice(pointer.child, buf[offset..][0..byte_len]).ptr,
                        .One => std.mem.bytesAsValue(pointer.child, buf[offset..][0..byte_len]),
                        else => comptime unreachable,
                    });
                }

                return result;
            }

            const info = @typeInfo(S).Struct;
            const fields = info.fields;
            const FieldId = std.meta.FieldEnum(S);

            const Offsets = std.enums.EnumFieldStruct(FieldId, usize, null);
            const Lengths = @Type(.{ .Struct = blk: {
                var new_fields = fields[0..].*;
                for (&new_fields) |*field| {
                    const pointer = @typeInfo(field.type).Pointer;
                    switch (pointer.size) {
                        .Slice, .Many => field.* = .{
                            .name = field.name,
                            .type = usize,
                            .alignment = 0,
                            .is_comptime = false,
                            .default_value = null,
                        },
                        .One => field.* = .{
                            .name = field.name,
                            .type = comptime_int,
                            .alignment = 0,
                            .is_comptime = true,
                            .default_value = @typeInfo(struct {
                                comptime comptime_int = 1,
                            }).Struct.fields[0].default_value,
                        },
                        else => @compileError("Other pointer sizes not supported"),
                    }
                }
                break :blk .{
                    .layout = .Auto,
                    .is_tuple = info.is_tuple,
                    .backing_integer = null,
                    .decls = &.{},
                    .fields = &new_fields,
                };
            } });

            const max_align = blk: {
                var max = 1;
                for (fields) |field| {
                    max = @max(max, @typeInfo(field.type).Pointer.alignment);
                }
                break :blk max;
            };
            const ordered_ids = &blk: {
                var ids: [fields.len]FieldId = std.enums.values(FieldId)[0..].*;

                @setEvalBranchQuota(ids.len * ids.len + 10);
                std.sort.insertionContext(0, ids.len, struct {
                    pub fn lessThan(a: usize, b: usize) bool {
                        const align_a = @typeInfo(fields[@intFromEnum(ids[a])].type).Pointer.alignment;
                        const align_b = @typeInfo(fields[@intFromEnum(ids[b])].type).Pointer.alignment;
                        return align_a > align_b;
                    }
                    pub fn swap(a: usize, b: usize) void {
                        std.mem.swap(&ids[a], &ids[b]);
                    }
                });

                break :blk ids;
            };
        };
    }
};

pub fn MetadataBasedAllocHelpers(comptime mem_align: comptime_int) type {
    return struct {
        pub const alignment = mem_align;
        pub const Metadata = extern struct {
            size: usize,

            pub const padded_size = std.mem.alignForward(usize, @sizeOf(Metadata), alignment);

            pub inline fn backingAllocation(md: *align(alignment) Metadata) []align(alignment) u8 {
                const base_ptr: [*]align(alignment) u8 = @alignCast(@ptrCast(md));
                return base_ptr[0 .. Metadata.padded_size + md.size];
            }
        };

        pub inline fn getMetadata(ptr: [*]align(alignment) u8) *align(alignment) Metadata {
            const base_ptr = ptr - Metadata.padded_size;
            return std.mem.bytesAsValue(Metadata, base_ptr[0..@sizeOf(Metadata)]);
        }

        pub fn alloc(ally: std.mem.Allocator, size: usize) ?[*]align(alignment) u8 {
            if (size == 0) return null;
            const aligned_len = Metadata.padded_size + size;
            const allocation = ally.alignedAlloc(u8, alignment, aligned_len) catch return null;
            std.mem.bytesAsValue(Metadata, allocation[0..@sizeOf(Metadata)]).* = .{
                .size = size,
            };
            return allocation[Metadata.padded_size..].ptr;
        }

        pub fn realloc(ally: std.mem.Allocator, old_ptr: [*]align(alignment) u8, new_size: usize) ?[*]align(alignment) u8 {
            const old_metadata = getMetadata(old_ptr);
            const old_allocation = old_metadata.backingAllocation();

            if (new_size == 0) {
                ally.free(old_allocation);
                return null;
            }

            const new_allocation = ally.realloc(old_allocation, Metadata.padded_size + new_size) catch return null;
            const new_metadata = std.mem.bytesAsValue(Metadata, new_allocation[0..@sizeOf(Metadata)]);
            new_metadata.* = .{
                .size = new_size,
            };
            return new_allocation[Metadata.padded_size..].ptr;
        }

        pub fn free(ally: std.mem.Allocator, ptr: [*]align(alignment) u8) void {
            const metadata = getMetadata(ptr);
            const allocation = metadata.backingAllocation();
            ally.free(allocation);
        }
    };
}

pub const InlineSlicer = struct {
    Elem: type,
    count: comptime_int,
    cursor: comptime_int,

    pub fn init(comptime Elem: type, comptime count: comptime_int) InlineSlicer {
        return .{
            .Elem = Elem,
            .count = count,
            .cursor = 0,
        };
    }

    pub inline fn next(
        comptime self: *InlineSlicer,
        buffer: *const [self.count]self.Elem,
        comptime advance: comptime_int,
    ) *const [advance]u8 {
        const remaining = buffer[self.cursor..];
        comptime if (advance > remaining.len) @compileError(std.fmt.comptimePrint(
            "Tried slicing {d} more elements, but there are only {d} remaining in the {d} element buffer",
            .{ advance, remaining.len, self.count },
        ));
        const result = remaining[0..advance];
        comptime self.cursor += result.len;
        return result;
    }

    pub inline fn nextRemaining(
        comptime self: *InlineSlicer,
        buffer: *const [self.count]self.Elem,
    ) *const [buffer.len - self.cursor]u8 {
        const remaining = buffer[self.cursor..];
        comptime self.cursor += remaining.len;
        return remaining;
    }

    pub inline fn finish(comptime self: *const InlineSlicer) void {
        _ = struct { // makes this lazy despite inlining
            comptime {
                assert(self.cursor <= self.count);
                if (self.cursor != self.count) @compileError(std.fmt.comptimePrint(
                    "{d} of {d} elements remain unused",
                    .{ self.count - self.cursor, self.count },
                ));
            }
        };
    }
};

pub fn slicesOverlap(a: anytype, b: anytype) bool {
    const a_bytes: []const u8 = std.mem.sliceAsBytes(a);
    const b_bytes: []const u8 = std.mem.sliceAsBytes(b);

    const a_start = @intFromPtr(a_bytes.ptr);
    const b_start = @intFromPtr(b_bytes.ptr);

    const a_end = @intFromPtr(a_bytes.ptr + a_bytes.len) - 1;
    const b_end = @intFromPtr(b_bytes.ptr + b_bytes.len) - 1;

    if (a_start >= b_start and a_start <= b_end) return true;
    if (a_end >= b_start and a_end <= b_end) return true;

    if (b_start >= a_start and b_start <= a_end) return true;
    if (b_end >= a_start and b_end <= a_end) return true;

    return false;
}

pub fn safeMemcpy(dst: anytype, src: anytype) void {
    assert(dst.len == src.len);
    if (!slicesOverlap(dst, src)) {
        @memcpy(dst, src);
        return;
    }
    switch (std.math.order(@intFromPtr(dst.ptr), @intFromPtr(src.ptr))) {
        .eq => return,
        .lt => for (dst, src) |*d, s| {
            d.* = s;
        },
        .gt => for (1..1 + dst.len) |r_i| {
            const i = dst.len - r_i;
            dst[i] = src[i];
        },
    }
}

/// Allocator which always fails to allocate, and presumes
/// resizing and freeing operations to be `unreachable`.
pub const empty_allocator = std.mem.Allocator{
    .ptr = undefined,
    .vtable = vtable: {
        const static = struct {
            fn alloc(ctx: *anyopaque, len: usize, ptr_align: u8, ret_addr: usize) ?[*]u8 {
                _ = ret_addr;
                _ = ptr_align;
                _ = len;
                _ = ctx;
                return null;
            }
            fn resize(ctx: *anyopaque, buf: []u8, buf_align: u8, new_len: usize, ret_addr: usize) bool {
                _ = ret_addr;
                _ = new_len;
                _ = buf_align;
                _ = buf;
                _ = ctx;
                unreachable;
            }
            fn free(ctx: *anyopaque, buf: []u8, buf_align: u8, ret_addr: usize) void {
                _ = ret_addr;
                _ = buf_align;
                _ = buf;
                _ = ctx;
                unreachable;
            }
        };
        break :vtable &std.mem.Allocator.VTable{
            .alloc = static.alloc,
            .resize = static.resize,
            .free = static.free,
        };
    },
};

pub fn fixedLenFmt(
    comptime fmt_str: []const u8,
    args: anytype,
    comptime reference_args: @TypeOf(args),
) error{ Overflow, Underflow }![std.fmt.count(fmt_str, reference_args)]u8 {
    const bounded = try boundedFmt(fmt_str, args, reference_args);
    if (bounded.len != bounded.buffer.len) return error.Underflow;
    return bounded.constSlice()[0..bounded.buffer.len].*;
}

pub fn boundedFmt(
    comptime fmt_str: []const u8,
    args: anytype,
    comptime reference_args: @TypeOf(args),
) error{Overflow}!std.BoundedArray(u8, std.fmt.count(fmt_str, reference_args)) {
    const len = comptime std.fmt.count(fmt_str, reference_args);
    var result: std.BoundedArray(u8, len) = .{};
    try result.writer().print(fmt_str, args);
    return result;
}

pub fn BoundedBufferArray(comptime T: type) type {
    return BoundedBufferArrayAligned(T, @alignOf(T));
}
pub fn BoundedBufferArrayAligned(comptime T: type, comptime alignment: comptime_int) type {
    return struct {
        buffer: Slice,
        len: usize = 0,
        const Self = @This();

        pub const Slice = []align(alignment) T;

        pub inline fn clear(self: *Self) void {
            self.len = 0;
        }

        pub inline fn capacity(self: Self) usize {
            return self.buffer.len;
        }

        pub inline fn slice(self: Self) Slice {
            return self.buffer[0..self.len];
        }

        pub inline fn getPtr(self: Self, index: usize) *T {
            return &self.slice()[index];
        }

        pub inline fn get(self: Self, index: usize) T {
            return self.getPtr(index);
        }

        pub inline fn set(self: Self, index: usize, value: T) void {
            self.getPtr(index).* = value;
        }

        pub fn addOne(self: *Self) error{Overflow}!*align(alignment) T {
            if (self.len == self.capacity()) return error.Overflow;
            return self.addOneAssumeCapacity();
        }

        pub fn addOneAssumeCapacity(self: *Self) *align(alignment) T {
            const index = self.len;
            assert(index < self.capacity());
            self.len += 1;
            return self.getPtr(index);
        }

        pub inline fn addManyAsSlice(self: *Self, count: usize) error{Overflow}![]align(alignment) T {
            if (self.len + count > self.capacity()) return error.Overflow;
            return self.addManyAsSliceAssumeCapacity(count);
        }

        pub fn addManyAsSliceAssumeCapacity(self: *Self, count: usize) []align(alignment) T {
            assert(self.len + count <= self.capacity());
            const prev_len = self.len;
            self.len += count;
            return self.slice()[prev_len..][0..count];
        }

        pub fn addManyAsArray(self: *Self, comptime count: usize) error{Overflow}!*align(alignment) [count]T {
            const result = try self.addManyAsSlice(count);
            return result[0..count];
        }

        pub fn addManyAsArrayAssumeCapacity(self: *Self, comptime count: usize) error{Overflow}!*align(alignment) [count]T {
            const result = self.addManyAsSliceAssumeCapacity(count);
            return result[0..count];
        }

        pub inline fn append(self: *Self, value: T) error{Overflow}!void {
            if (self.len == self.capacity()) return error.Overflow;
            self.addOneAssumeCapacity().* = value;
        }

        pub inline fn appendAssumingCapacity(self: *Self, value: T) void {
            self.addOneAssumeCapacity().* = value;
        }

        pub inline fn appendSlice(self: *Self, values: []const T) error{Overflow}!void {
            @memcpy(try self.addManyAsSlice(values.len), values);
        }

        pub inline fn appendSliceAssumingCapacity(self: *Self, values: []const T) void {
            @memcpy(self.addManyAsSliceAssumeCapacity(values.len), values);
        }

        pub inline fn insert(self: *Self, index: usize, value: T) error{Overflow}!void {
            if (self.len == self.capacity()) return error.Overflow;
            self.insertAssumeCapacity(index, value);
        }

        pub fn insertAssumeCapacity(self: *Self, index: usize, value: T) void {
            assert(index <= self.len);
            _ = self.addOneAssumeCapacity();
            const dst = self.slice()[index + 1 .. self.len];
            const src = self.slice()[index .. self.len - 1];
            std.mem.copyBackwards(T, dst, src);
            self.set(index, value);
        }

        pub fn insertSlice(self: *Self, index: usize, values: []const T) error{Overflow}!void {
            _ = try self.addManyAsSlice(values.len);
            const dst = self.slice()[index + values.len .. self.len];
            const src = self.slice()[index .. self.len - values.len];
            std.mem.copyBackwards(T, dst, src);
            @memcpy(self.slice()[index..][0..values.len], values);
        }

        pub fn insertSliceAssumeCapacity(self: *Self, index: usize, values: []const T) void {
            _ = self.addManyAsSliceAssumeCapacity(values.len);
            const dst = self.slice()[index + values.len .. self.len];
            const src = self.slice()[index .. self.len - values.len];
            std.mem.copyBackwards(T, dst, src);
            @memcpy(self.slice()[index..][0..values.len], values);
        }

        pub fn popOrNull(self: *Self) ?T {
            if (self.len == 0) return null;
            const value = self.get(self.len - 1);
            self.len -= 1;
            return value;
        }

        pub inline fn pop(self: *Self) T {
            return self.popOrNull().?;
        }

        pub fn unusedCapacitySlice(self: Self) []T {
            return self.buffer[self.len..];
        }

        pub const Writer = std.io.Writer(*Self, error{Overflow}, appendWrite);
        pub inline fn writer(self: *Self) Writer {
            return .{ .context = self };
        }
        fn appendWrite(self: *Self, bytes: []const u8) error{Overflow}!usize {
            try self.appendSlice(bytes);
            return bytes.len;
        }
    };
}

pub inline fn hasherWriter(hasher: anytype) HasherWriter(@TypeOf(hasher.*)).Writer {
    return .{ .context = .{ .hasher = hasher } };
}

pub fn HasherWriter(comptime Hasher: type) type {
    return struct {
        hasher: *Hasher,
        const Self = @This();

        pub const Writer = std.io.Writer(Self, Self.Error, Self.write);

        const Error = error{};
        fn write(self: Self, bytes: []const u8) Error!usize {
            self.hasher.update(bytes);
            return bytes.len;
        }
    };
}

pub fn factorial(comptime n: u8) comptime_int {
    var r = 1;
    @setEvalBranchQuota(n +| 2);
    for (1..(n + 1)) |i| r *= i;
    return r;
}

pub fn numChosen(comptime m: u8, comptime n: u8) comptime_int {
    return factorial(m) / (factorial(n) * factorial(m - n));
}

pub fn ChosenType(comptime m: u8, comptime n: u8) type {
    const t = numChosen(m, n);
    return [t][n]u8;
}

pub inline fn choose(comptime l: []const u8, comptime k: u8) ChosenType(l.len, k) {
    comptime {
        assert(l.len >= k);
        assert(k > 0);
        var ret = std.mem.zeroes(ChosenType(l.len, k));

        if (k == 1) {
            inline for (0..l.len) |i| {
                ret[i] = [k]u8{l[i]};
            }
            return ret;
        }

        const chosen = choose(l[1..], k - 1);
        var i = 0;
        for (0..(l.len - 1)) |m| {
            for (0..chosen.len) |n| {
                if (l[m] >= chosen[n][0]) continue;
                ret[i][0] = l[m];
                for (0..chosen[n].len) |j| {
                    ret[i][j + 1] = chosen[n][j];
                }
                i += 1;
            }
        }
        return ret;
    }
}
