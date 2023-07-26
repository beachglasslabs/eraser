const std = @import("std");

pub const DataOrder = enum {
    row,
    col,
};

const MatrixData = union(DataOrder) {
    row: u8,
    col: u8,
};

allocator: std.mem.Allocator,
num_rows: u8 = undefined,
num_cols: u8 = undefined,
mdata: std.MultiArrayList(MatrixData) = undefined,
mtype: DataOrder = undefined,

const Self = @This();

// 2^n field
pub fn init(allocator: std.mem.Allocator, data_order: DataOrder, num_rows: usize, num_cols: usize) !Self {
    var list = std.MultiArrayList(MatrixData){};
    try list.ensureTotalCapacity(allocator, num_rows * num_cols);
    for (0..num_rows * num_cols) |_| {
        switch (data_order) {
            .row => list.appendAssumeCapacity(.{ .row = 0 }),
            .col => list.appendAssumeCapacity(.{ .col = 0 }),
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
    defer self.mdata.deinit(self.allocator);
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
            return self.mdata.get(row * self.num_cols + col).row;
        },
        .col => {
            return self.mdata.get(col * self.num_rows + row).col;
        },
    }
}

pub fn set(self: *Self, row: usize, col: usize, value: u8) void {
    std.debug.assert(row < self.num_rows and col < self.num_cols);
    switch (self.mtype) {
        .row => {
            const i = row * self.num_cols + col;
            self.mdata.set(i, .{ .row = value });
        },
        .col => {
            const i = col * self.num_rows + row;
            self.mdata.set(i, .{ .col = value });
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

pub fn getRow(self: *const Self, row: usize) ![]u8 {
    std.debug.assert(row < self.num_rows);
    var list = try std.ArrayList(u8).initCapacity(self.allocator, self.num_cols);
    defer list.deinit();
    for (0..self.num_cols) |c| {
        list.appendAssumeCapacity(self.get(row, c));
    }
    return list.toOwnedSlice();
}

pub fn getCol(self: *const Self, col: usize) ![]u8 {
    std.debug.assert(col < self.num_cols);
    var list = try std.ArrayList(u8).initCapacity(self.allocator, self.num_rows);
    defer list.deinit();
    for (0..self.num_rows) |r| {
        list.appendAssumeCapacity(self.get(r, col));
    }
    return list.toOwnedSlice();
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
    var m = try Self.init(std.testing.allocator, DataOrder.row, 3, 2);
    defer m.deinit();
    m.set(0, 0, 1);
    m.set(0, 1, 2);
    m.set(1, 1, 4);
    m.set(2, 0, 5);
    m.print();
    var col0 = try m.getCol(0);
    var col1 = try m.getCol(1);
    defer {
        std.testing.allocator.free(col0);
        std.testing.allocator.free(col1);
    }
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

    var row0 = try m.getRow(0);
    var row1 = try m.getRow(1);
    var row2 = try m.getRow(2);
    defer {
        std.testing.allocator.free(row0);
        std.testing.allocator.free(row1);
        std.testing.allocator.free(row2);
    }
    try std.testing.expectEqualSlices(u8, row0, &[_]u8{ 1, 4, 7 });
    try std.testing.expectEqualSlices(u8, row1, &[_]u8{ 2, 5, 8 });
    try std.testing.expectEqualSlices(u8, row2, &[_]u8{ 3, 6, 9 });

    var col0 = try m.getCol(0);
    var col1 = try m.getCol(1);
    var col2 = try m.getCol(2);
    defer {
        std.testing.allocator.free(col0);
        std.testing.allocator.free(col1);
        std.testing.allocator.free(col2);
    }
    try std.testing.expectEqualSlices(u8, col0, &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, col1, &[_]u8{ 4, 5, 6 });
    try std.testing.expectEqualSlices(u8, col2, &[_]u8{ 7, 8, 9 });
}

test "matrix transposition" {
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

    m.transpose();
    m.print();

    var row0 = try m.getRow(0);
    var row1 = try m.getRow(1);
    var row2 = try m.getRow(2);
    defer {
        std.testing.allocator.free(row0);
        std.testing.allocator.free(row1);
        std.testing.allocator.free(row2);
    }
    try std.testing.expectEqualSlices(u8, row0, &[_]u8{ 1, 2, 3 });
    try std.testing.expectEqualSlices(u8, row1, &[_]u8{ 4, 5, 6 });
    try std.testing.expectEqualSlices(u8, row2, &[_]u8{ 7, 8, 9 });

    var col0 = try m.getCol(0);
    var col1 = try m.getCol(1);
    var col2 = try m.getCol(2);
    defer {
        std.testing.allocator.free(col0);
        std.testing.allocator.free(col1);
        std.testing.allocator.free(col2);
    }
    try std.testing.expectEqualSlices(u8, col0, &[_]u8{ 1, 4, 7 });
    try std.testing.expectEqualSlices(u8, col1, &[_]u8{ 2, 5, 8 });
    try std.testing.expectEqualSlices(u8, col2, &[_]u8{ 3, 6, 9 });
}
