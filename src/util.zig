const std = @import("std");
const assert = std.debug.assert;

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

pub inline fn match2(a: anytype, b: anytype) u2 {
    const Ta = @TypeOf(a);
    const Tb = @TypeOf(b);
    if (Ta == comptime_int) return match2(@as(u1, a), @as(Tb, b));
    if (Tb == comptime_int) return match2(@as(Ta, a), @as(u1, b));
    const Bits = packed struct { a: bool, b: bool };
    const bits: Bits = .{ .a = @bitCast(a), .b = @bitCast(b) };
    return @bitCast(bits);
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

pub inline fn redirectingReader(reader: anytype, writer: anytype) RedirectingReader(@TypeOf(reader), @TypeOf(writer)) {
    return .{ .inner = reader, .writer = writer };
}
pub fn RedirectingReader(comptime InnerReader: type, comptime Writer: type) type {
    return struct {
        inner: InnerReader,
        writer: Writer,
        const Self = @This();

        pub const Reader = std.io.Reader(Self, Self.Error, Self.read);
        const Error = InnerReader.Error || Writer.Error;
        pub inline fn reader(self: Self) Reader {
            return .{ .context = self };
        }

        fn read(self: Self, buf: []u8) Error!usize {
            const count = try self.inner.read(buf);
            try self.writer.writeAll(buf[0..count]);
        }
    };
}

pub inline fn sha256DigestCalcReader(
    hasher: *std.crypto.hash.sha2.Sha256,
    inner: anytype,
) Sha256DigestCalcReader(@TypeOf(inner)) {
    return .{
        .inner = inner,
        .hasher = hasher,
    };
}
pub fn Sha256DigestCalcReader(comptime InnerReader: type) type {
    return struct {
        hasher: *Sha256,
        inner: Inner,
        const Self = @This();

        pub const Inner = InnerReader;

        pub const Reader = std.io.Reader(Self, Inner.Error, Self.read);
        pub inline fn reader(self: Self) Reader {
            return .{ .context = self };
        }

        const Sha256 = std.crypto.hash.sha2.Sha256;
        fn read(self: Self, buf: []u8) Inner.Error!usize {
            const count = try self.inner.read(buf);
            self.hasher.update(buf[0..count]);
            return count;
        }
    };
}
pub inline fn sha256DigestCalcWriter(
    hasher: *std.crypto.hash.sha2.Sha256,
    inner: anytype,
) Sha256DigestCalcWriter(@TypeOf(inner)) {
    return .{
        .inner = inner,
        .hasher = hasher,
    };
}
pub fn Sha256DigestCalcWriter(comptime InnerWriter: type) type {
    return struct {
        hasher: *Sha256,
        inner: Inner,
        const Self = @This();

        pub const Inner = InnerWriter;

        pub const Writer = std.io.Writer(Self, Inner.Error, Self.write);
        pub inline fn writer(self: Self) Writer {
            return .{ .context = self };
        }

        const Sha256 = std.crypto.hash.sha2.Sha256;
        fn write(self: Self, bytes: []const u8) Inner.Error!usize {
            const count = try self.inner.write(bytes);
            self.hasher.update(bytes[0..count]);
            return count;
        }
    };
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

        var c = choose(l[1..], k - 1);
        var i = 0;
        for (0..(l.len - 1)) |m| {
            for (0..c.len) |n| {
                if (l[m] >= c[n][0]) continue;
                ret[i][0] = l[m];
                for (0..c[n].len) |j| {
                    ret[i][j + 1] = c[n][j];
                }
                i += 1;
            }
        }
        return ret;
    }
}
