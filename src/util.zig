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

pub inline fn ptrSizedReader(reader_ptr: anytype) PtrSizedReader(@TypeOf(reader_ptr.*)) {
    return .{ .context = reader_ptr };
}
pub fn PtrSizedReader(comptime WrappedReader: type) type {
    const gen = struct {
        fn read(ptr: *const WrappedReader, buf: []u8) WrappedReader.Error!usize {
            return @call(.always_inline, WrappedReader.read, .{ ptr.*, buf });
        }
    };
    return std.io.Reader(*const WrappedReader, WrappedReader.Error, gen.read);
}
comptime {
    const Wrapped = std.io.PeekStream(.{ .Static = 4096 }, std.fs.File.Reader);
    assert(@sizeOf(PtrSizedReader(Wrapped.Reader)) == @sizeOf(*const Wrapped.Reader));
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
