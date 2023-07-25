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

pub fn get(self: *Self, row: usize, col: usize) u8 {
    switch (self.mtype) {
        .row => {
            return self.mdata.get(row * self.num_cols + col).row;
        },
        .col => {
            return self.mdata.get(col * self.num_rows + row).col;
        },
    }
}

pub fn getRow(self: *Self, row: usize) ![]u8 {
    var list = try std.ArrayList(u8).initCapacity(self.allocator, self.num_cols);
    defer list.deinit();
    switch (self.mtype) {
        .row => {
            for (0..self.num_cols) |c| {
                list.appendAssumeCapacity(self.mdata.items(.data)[row * self.num_cols + c].row);
            }
        },
        .col => {
            for (0..self.num_cols) |c| {
                list.appendAssumeCapacity(self.get(row, c));
            }
        },
    }
    return list.toOwnedSlice();
}

pub fn getCol(self: *Self, col: usize) ![]u8 {
    var list = try std.ArrayList(u8).initCapacity(self.allocator, self.num_rows);
    defer list.deinit();
    switch (self.mtype) {
        .row => {
            for (0..self.num_rows) |r| {
                list.appendAssumeCapacity(self.get(r, col));
            }
        },
        .col => {
            for (0..self.num_rows) |r| {
                list.appendAssumeCapacity(self.mdata.items(.data)[col * self.num_rows + r].col);
            }
        },
    }
    return list.toOwnedSlice();
}

pub fn set(self: *Self, row: usize, col: usize, value: u8) void {
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

pub fn print(self: *Self) void {
    return switch (self.mtype) {
        .row => {
            std.debug.print("{d}x{d} row ->\n", .{ self.num_rows, self.num_cols });
            for (0..self.num_rows) |r| {
                for (0..self.num_cols) |c| {
                    std.debug.print("{d} ", .{self.get(r, c)});
                }
                std.debug.print("\n", .{});
            }
        },
        .col => {
            std.debug.print("{d}x{d} col ->\n", .{ self.num_cols, self.num_rows });
            for (0..self.num_cols) |c| {
                for (0..self.num_rows) |r| {
                    std.debug.print("{d} ", .{self.get(r, c)});
                }
                std.debug.print("\n", .{});
            }
        },
    };
}
