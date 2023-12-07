const std = @import("std");

pub const DataOrder = enum {
    row,
    col,
};

pub fn Matrix(comptime m: comptime_int, comptime n: comptime_int) type {
    return struct {
        allocator: std.mem.Allocator = undefined,
        mdata: std.ArrayList(u8) = undefined,
        mtype: DataOrder = undefined,
        comptime numRows: u8 = m,
        comptime numCols: u8 = n,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator, data_order: DataOrder) !Self {
            var list = try std.ArrayList(u8).initCapacity(allocator, m * n);
            list.appendSliceAssumeCapacity(&std.mem.zeroes([m * n]u8));

            return .{
                .allocator = allocator,
                .mtype = data_order,
                .mdata = list,
            };
        }

        pub fn deinit(self: *Self) void {
            defer self.mdata.deinit();
        }

        pub fn get(self: *const Self, row: usize, col: usize) u8 {
            std.debug.assert(row < m and col < n);
            switch (self.mtype) {
                .row => {
                    const i = row * n + col;
                    return self.mdata.items[i];
                },
                .col => {
                    const i = col * m + row;
                    return self.mdata.items[i];
                },
            }
        }

        pub fn set(self: *Self, row: usize, col: usize, value: u8) void {
            std.debug.assert(row < m and col < n);
            switch (self.mtype) {
                .row => {
                    const i = row * n + col;
                    self.mdata.items[i] = value;
                },
                .col => {
                    const i = col * m + row;
                    self.mdata.items[i] = value;
                },
            }
        }

        pub fn transpose(self: *Self) void {
            std.debug.assert(m == n);
            for (0..m) |r| {
                for (0..n) |c| {
                    if (r == c) break;
                    const t = self.get(r, c);
                    self.set(r, c, self.get(c, r));
                    self.set(c, r, t);
                }
            }
        }

        // return eithers a row or a column based on matrix data order
        // use getRow() or getCol() if you want row/col regardless of data order
        pub fn getSlice(self: *const Self, rc: usize) []u8 {
            switch (self.mtype) {
                .row => {
                    std.debug.assert(rc < m);
                    const i = rc * n;
                    return self.mdata.items[i .. i + n];
                },
                .col => {
                    std.debug.assert(rc < n);
                    const i = rc * m;
                    return self.mdata.items[i .. i + m];
                },
            }
        }

        pub fn getRow(self: *const Self, row: usize) [n]u8 {
            switch (self.mtype) {
                .row => {
                    std.debug.assert(row < m);
                    const i = row * n;
                    var list: [n]u8 = std.mem.zeroes([n]u8);
                    inline for (0..n, self.mdata.items[i .. i + n]) |j, v| {
                        list[j] = v;
                    }
                    return list;
                },
                .col => {
                    var list: [n]u8 = std.mem.zeroes([n]u8);
                    for (0..n) |i| {
                        list[i] = self.get(row, i);
                    }
                    return list;
                },
            }
        }

        pub fn getCol(self: *const Self, col: usize) [m]u8 {
            switch (self.mtype) {
                .row => {
                    var list: [m]u8 = std.mem.zeroes([m]u8);
                    for (0..m) |i| {
                        list[i] = self.get(i, col);
                    }
                    return list;
                },
                .col => {
                    std.debug.assert(col < n);
                    const i = col * m;
                    var list: [m]u8 = std.mem.zeroes([m]u8);
                    inline for (0..m, self.mdata.items[i .. i + m]) |j, v| {
                        list[j] = v;
                    }
                    return list;
                },
            }
        }

        fn setSlice(self: *Self, rc: usize, new_rc: []const u8) void {
            switch (self.mtype) {
                .row => {
                    std.debug.assert(rc < m and new_rc.len >= n);
                    const i = rc * n;
                    self.mdata.replaceRange(i, n, new_rc[0..n]) catch return;
                },
                .col => {
                    std.debug.assert(rc < n and new_rc.len >= m);
                    const i = rc * m;
                    self.mdata.replaceRange(i, m, new_rc[0..m]) catch return;
                },
            }
        }

        pub fn setRow(self: *Self, row: usize, new_row: []const u8) void {
            switch (self.mtype) {
                .row => {
                    self.setSlice(row, new_row);
                },
                .col => {
                    std.debug.assert(row < m and new_row.len >= n);
                    for (0..n) |i| {
                        self.set(row, i, new_row[i]);
                    }
                },
            }
        }

        pub fn setCol(self: *Self, col: usize, new_col: []const u8) void {
            switch (self.mtype) {
                .row => {
                    std.debug.assert(col < n and new_col.len >= m);
                    for (0..m) |i| {
                        self.set(i, col, new_col[i]);
                    }
                },
                .col => {
                    self.setSlice(col, new_col);
                },
            }
        }

        pub fn format(self: *const Self, comptime _: []const u8, _: std.fmt.FormatOptions, stream: anytype) !void {
            switch (self.mtype) {
                .row => {
                    try stream.print("\n{d}x{d} row ->\n", .{ m, n });
                    for (0..m) |r| {
                        for (0..n) |c| {
                            try stream.print("{d} ", .{self.get(r, c)});
                        }
                        try stream.print("\n", .{});
                    }
                },
                .col => {
                    try stream.print("\n{d}x{d} col ->\n", .{ m, n });
                    for (0..n) |c| {
                        for (0..m) |r| {
                            try stream.print("{d} ", .{self.get(r, c)});
                        }
                        try stream.print("\n", .{});
                    }
                },
            }
        }
    };
}

test "basic matrix" {
    var m = try Matrix(3, 2).init(std.testing.allocator, DataOrder.col);
    defer m.deinit();
    m.set(0, 0, 1);
    m.set(0, 1, 2);
    m.set(1, 1, 4);
    m.set(2, 0, 5);
    try std.testing.expectEqualSlices(u8, m.getSlice(0), &[_]u8{ 1, 0, 5 });
    try std.testing.expectEqualSlices(u8, m.getSlice(1), &[_]u8{ 2, 4, 0 });
    m.setCol(1, &[_]u8{ 7, 8, 9 });
    try std.testing.expectEqualSlices(u8, m.getSlice(1), &[_]u8{ 7, 8, 9 });
    m.setRow(1, &[_]u8{ 6, 7 });
    try std.testing.expectEqual(m.get(1, 0), 6);
    try std.testing.expectEqual(m.get(1, 1), 7);
}

test "square matrix" {
    var m = try Matrix(3, 3).init(std.testing.allocator, DataOrder.col);
    defer m.deinit();
    m.set(0, 0, 1);
    m.set(1, 0, 2);
    m.set(2, 0, 3);
    m.set(0, 1, 4);
    m.set(1, 1, 5);
    m.set(2, 1, 6);
    m.set(0, 2, 7);
    m.set(1, 2, 8);
    m.set(2, 2, 9);

    try std.testing.expectEqualSlices(u8, m.getSlice(0), &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, m.getSlice(1), &[_]u8{ 4, 5, 6 });
    try std.testing.expectEqualSlices(u8, m.getSlice(2), &[_]u8{ 7, 8, 9 });
}

test "matrix transposition" {
    var m = try Matrix(3, 3).init(std.testing.allocator, DataOrder.row);
    defer m.deinit();
    m.set(0, 0, 1);
    m.set(1, 0, 2);
    m.set(2, 0, 3);
    m.set(0, 1, 4);
    m.set(1, 1, 5);
    m.set(2, 1, 6);
    m.set(0, 2, 7);
    m.set(1, 2, 8);
    m.set(2, 2, 9);

    m.transpose();

    try std.testing.expectEqualSlices(u8, m.getSlice(0), &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, m.getSlice(1), &[_]u8{ 4, 5, 6 });
    try std.testing.expectEqualSlices(u8, m.getSlice(2), &[_]u8{ 7, 8, 9 });
}

test "rows and cols" {
    var m = try Matrix(4, 3).init(std.testing.allocator, DataOrder.row);
    defer m.deinit();
    m.setRow(0, &[_]u8{ 1, 2, 3 });
    m.setRow(1, &[_]u8{ 5, 6, 7 });
    m.setRow(2, &[_]u8{ 9, 10, 11 });
    m.setRow(3, &[_]u8{ 13, 14, 15 });

    try std.testing.expectEqualSlices(u8, &m.getRow(0), &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, &m.getRow(1), &[_]u8{ 5, 6, 7 });
    try std.testing.expectEqualSlices(u8, &m.getRow(2), &[_]u8{ 9, 10, 11 });
    try std.testing.expectEqualSlices(u8, &m.getRow(3), &[_]u8{ 13, 14, 15 });

    m.setCol(1, &[_]u8{ 4, 8, 12, 16 });

    try std.testing.expectEqualSlices(u8, &m.getRow(0), &[_]u8{ 1, 4, 3 });
    try std.testing.expectEqualSlices(u8, &m.getRow(1), &[_]u8{ 5, 8, 7 });
    try std.testing.expectEqualSlices(u8, &m.getRow(2), &[_]u8{ 9, 12, 11 });
    try std.testing.expectEqualSlices(u8, &m.getRow(3), &[_]u8{ 13, 16, 15 });

    try std.testing.expectEqualSlices(u8, &m.getCol(0), &[_]u8{ 1, 5, 9, 13 });
    try std.testing.expectEqualSlices(u8, &m.getCol(1), &[_]u8{ 4, 8, 12, 16 });
    try std.testing.expectEqualSlices(u8, &m.getCol(2), &[_]u8{ 3, 7, 11, 15 });

    var m2 = try Matrix(3, 2).init(std.testing.allocator, DataOrder.col);
    defer m2.deinit();
    m2.setCol(0, &[_]u8{ 1, 3, 7 });
    m2.setCol(1, &[_]u8{ 2, 5, 2 });
    try std.testing.expectEqualSlices(u8, &m2.getCol(0), &[_]u8{ 1, 3, 7 });
    m2.setRow(1, &[_]u8{ 9, 8 });

    try std.testing.expectEqualSlices(u8, &m2.getRow(0), &[_]u8{ 1, 2 });
    try std.testing.expectEqualSlices(u8, &m2.getRow(1), &[_]u8{ 9, 8 });
    try std.testing.expectEqualSlices(u8, &m2.getRow(2), &[_]u8{ 7, 2 });
}
