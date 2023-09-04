const std = @import("std");
const assert = std.debug.assert;

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

pub fn BoundedBufferArray(comptime T: type) type {
    return BoundedBufferArrayAligned(T, @alignOf(T));
}
pub fn BoundedBufferArrayAligned(comptime T: type, comptime alignment: comptime_int) type {
    return struct {
        buffer: Slice,
        len: usize = 0,
        const Self = @This();

        pub const Slice = []align(alignment) T;

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
            const prev_len = self.items.len;
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
