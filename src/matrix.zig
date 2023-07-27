const std = @import("std");

pub const DataOrder = enum {
    row,
    col,
};

allocator: std.mem.Allocator,
num_rows: u8 = undefined,
num_cols: u8 = undefined,
mdata: std.ArrayList(u8) = undefined,
mtype: DataOrder = undefined,

const Self = @This();

// 2^n field
pub fn init(allocator: std.mem.Allocator, data_order: DataOrder, num_rows: usize, num_cols: usize) !Self {
    var list = try std.ArrayList(u8).initCapacity(allocator, num_rows * num_cols);
    for (0..num_rows * num_cols) |_| {
        switch (data_order) {
            .row => list.appendAssumeCapacity(0),
            .col => list.appendAssumeCapacity(0),
        }
    }

    return .{
        .allocator = allocator,
        .num_rows = @intCast(num_rows),
        .num_cols = @intCast(num_cols),
        .mtype = data_order,
        .mdata = list,
    };
}

pub fn deinit(self: *Self) void {
    defer self.mdata.deinit();
}

pub fn numRows(self: *const Self) u8 {
    return self.num_rows;
}

pub fn numCols(self: *const Self) u8 {
    return self.num_Cols;
}

pub fn get(self: *const Self, row: usize, col: usize) u8 {
    std.debug.assert(row < self.num_rows and col < self.num_cols);
    switch (self.mtype) {
        .row => {
            const i = row * self.num_cols + col;
            return self.mdata.items[i];
        },
        .col => {
            const i = col * self.num_rows + row;
            return self.mdata.items[i];
        },
    }
}

pub fn set(self: *Self, row: usize, col: usize, value: u8) void {
    std.debug.assert(row < self.num_rows and col < self.num_cols);
    switch (self.mtype) {
        .row => {
            const i = row * self.num_cols + col;
            self.mdata.items[i] = value;
        },
        .col => {
            const i = col * self.num_rows + row;
            self.mdata.items[i] = value;
        },
    }
}

pub fn transpose(self: *Self) void {
    std.debug.assert(self.num_rows == self.num_cols);
    for (0..self.num_rows) |r| {
        for (0..self.num_cols) |c| {
            if (r == c) break;
            var t = self.get(r, c);
            self.set(r, c, self.get(c, r));
            self.set(c, r, t);
        }
    }
}

fn getSlice(self: *const Self, rc: usize) []u8 {
    switch (self.mtype) {
        .row => {
            std.debug.assert(rc < self.num_rows);
            const i = rc * self.num_cols;
            return self.mdata.items[i .. i + self.num_cols];
        },
        .col => {
            std.debug.assert(rc < self.num_cols);
            const i = rc * self.num_rows;
            return self.mdata.items[i .. i + self.num_rows];
        },
    }
}

pub fn getRow(self: *const Self, row: usize) []u8 {
    std.debug.print("mtype={}\n", .{self.mtype});
    switch (self.mtype) {
        .row => {
            return self.getSlice(row);
        },
        .col => {
            std.debug.print("matrix data is columnn based, use get() or getCol() instead.\n", .{});
            return self.getSlice(row);
        },
    }
}

pub fn getCol(self: *const Self, col: usize) []u8 {
    std.debug.print("mtype={}\n", .{self.mtype});
    switch (self.mtype) {
        .col => {
            return self.getSlice(col);
        },
        .row => {
            std.debug.print("matrix data is row based, use get() or getRow() instead.\n", .{});
            return self.getSlice(col);
        },
    }
}

pub fn print(self: *const Self) void {
    return switch (self.mtype) {
        .row => {
            std.debug.print("\n{d}x{d} row ->\n", .{ self.num_rows, self.num_cols });
            for (0..self.num_rows) |r| {
                for (0..self.num_cols) |c| {
                    std.debug.print("{d} ", .{self.get(r, c)});
                }
                std.debug.print("\n", .{});
            }
        },
        .col => {
            std.debug.print("\n{d}x{d} col ->\n", .{ self.num_cols, self.num_rows });
            for (0..self.num_cols) |c| {
                for (0..self.num_rows) |r| {
                    std.debug.print("{d} ", .{self.get(r, c)});
                }
                std.debug.print("\n", .{});
            }
        },
    };
}

test "basic matrix" {
    var m = try Self.init(std.testing.allocator, DataOrder.col, 3, 2);
    defer m.deinit();
    m.set(0, 0, 1);
    m.set(0, 1, 2);
    m.set(1, 1, 4);
    m.set(2, 0, 5);
    m.print();
    var col0 = m.getCol(0);
    var col1 = m.getCol(1);
    try std.testing.expectEqualSlices(u8, col0, &[_]u8{ 1, 0, 5 });
    try std.testing.expectEqualSlices(u8, col1, &[_]u8{ 2, 4, 0 });
}

test "square matrix" {
    var m = try Self.init(std.testing.allocator, DataOrder.col, 3, 3);
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
    m.print();

    var col0 = m.getCol(0);
    var col1 = m.getCol(1);
    var col2 = m.getCol(2);
    try std.testing.expectEqualSlices(u8, col0, &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, col1, &[_]u8{ 4, 5, 6 });
    try std.testing.expectEqualSlices(u8, col2, &[_]u8{ 7, 8, 9 });
}

test "matrix transposition" {
    var m = try Self.init(std.testing.allocator, DataOrder.row, 3, 3);
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
    m.print();

    var row0 = m.getRow(0);
    var row1 = m.getRow(1);
    var row2 = m.getRow(2);
    try std.testing.expectEqualSlices(u8, row0, &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, row1, &[_]u8{ 4, 5, 6 });
    try std.testing.expectEqualSlices(u8, row2, &[_]u8{ 7, 8, 9 });
}
