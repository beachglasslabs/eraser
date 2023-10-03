const std = @import("std");
const assert = std.debug.assert;

const util = @import("util.zig");

const Unmanaged = @This();
list: HeaderList = .{},
index: HeaderIndex = .{},
owned: bool = true,

const Managed = std.http.Headers;
const HeaderIndex = std.HashMapUnmanaged([]const u8, HeaderIndexList, CaseInsensitiveStringContext, std.hash_map.default_max_load_percentage);
const HeaderList = std.ArrayListUnmanaged(Field);

const Field = std.meta.Child(std.meta.FieldType(Managed, .list).Slice);
const HeaderIndexList = std.ArrayListUnmanaged(usize);
const CaseInsensitiveStringContext = T: {
    const HashMapManaged = std.meta.FieldType(Managed, .index).Managed;
    const Ctx = std.meta.FieldType(HashMapManaged, .ctx);
    break :T Ctx;
};

pub fn toManaged(unmanaged: Unmanaged, allocator: std.mem.Allocator) Managed {
    return .{
        .allocator = allocator,
        .list = unmanaged.list,
        .index = unmanaged.index,
        .owned = unmanaged.owned,
    };
}

pub inline fn fromManaged(managed: Managed) Unmanaged {
    return .{
        .list = managed.list,
        .index = managed.index,
        .owned = managed.owned,
    };
}

pub fn deinit(headers: *Unmanaged, allocator: std.mem.Allocator) void {
    var managed = headers.toManaged(allocator);
    defer headers.* = fromManaged(managed);
    managed.deinit();
}

pub fn append(headers: *Unmanaged, allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    var managed = headers.toManaged(allocator);
    defer headers.* = fromManaged(managed);
    return managed.append(name, value);
}

pub fn contains(headers: Unmanaged, name: []const u8) bool {
    return headers.toManaged(util.empty_allocator).contains(name);
}

pub fn delete(headers: *Unmanaged, allocator: std.mem.Allocator, name: []const u8) bool {
    var managed = headers.toManaged(allocator);
    defer headers.* = fromManaged(managed);
    return managed.delete(name);
}

pub fn firstIndexOf(headers: Unmanaged, name: []const u8) ?usize {
    return headers.toManaged(util.empty_allocator).firstIndexOf(name);
}

pub fn getIndices(headers: Unmanaged, name: []const u8) ?[]const usize {
    return headers.toManaged(util.empty_allocator).getIndices(name);
}

pub fn getFirstEntry(headers: Unmanaged, name: []const u8) ?Field {
    return headers.toManaged(util.empty_allocator).getFirstEntry(name);
}

pub fn getEntries(headers: Unmanaged, allocator: std.mem.Allocator, name: []const u8) !?[]const Field {
    return headers.toManaged(util.empty_allocator).getEntries(allocator, name);
}

pub fn getFirstValue(headers: Unmanaged, name: []const u8) ?[]const u8 {
    return headers.toManaged(util.empty_allocator).getFirstValue(name);
}

pub fn getValues(headers: Unmanaged, allocator: std.mem.Allocator, name: []const u8) !?[]const []const u8 {
    return headers.toManaged(util.empty_allocator).getValues(allocator, name);
}

pub fn sort(headers: *Unmanaged) void {
    return headers.toManaged(util.empty_allocator).sort();
}

pub fn format(
    headers: Unmanaged,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    out_stream: anytype,
) !void {
    const managed = headers.toManaged(util.empty_allocator);
    return managed.format(fmt, options, out_stream);
}

pub fn formatCommaSeparated(
    headers: Unmanaged,
    name: []const u8,
    out_stream: anytype,
) !void {
    const managed = headers.toManaged(util.empty_allocator);
    return managed.formatCommaSeparated(name, out_stream);
}

pub fn clearAndFree(headers: *Unmanaged, allocator: std.mem.Allocator) void {
    var managed = headers.toManaged(allocator);
    defer headers.* = fromManaged(managed);
    return managed.clearAndFree();
}

pub fn clearRetainingCapacity(headers: *Unmanaged, allocator: std.mem.Allocator) void {
    var managed = headers.toManaged(allocator);
    defer headers.* = fromManaged(managed);
    return managed.clearRetainingCapacity();
}

pub fn clone(headers: Unmanaged, allocator: std.mem.Allocator) !Unmanaged {
    const managed = headers.toManaged(util.empty_allocator);
    return fromManaged(try managed.clone(allocator));
}
