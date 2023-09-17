//! Used to clear all the buckets in google cloud
//! Should *ONLY* be used during testing, deletes
//! *ALL* objects indiscriminately.
//! Calls the system command 'gcloud', once to list
//! the buckets, a second time to list the objects,
//! and a third time to delete them.
const std = @import("std");

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var list_buckets = std.ChildProcess.init(&.{ "gcloud", "storage", "ls" }, arena);
    list_buckets.stdout_behavior = .Pipe;
    list_buckets.stderr_behavior = .Pipe;
    try list_buckets.spawn();

    var stderr_buf = std.ArrayList(u8).init(arena);
    defer stderr_buf.deinit();

    var list_buckets_stdout = std.ArrayList(u8).init(arena);
    defer list_buckets_stdout.deinit();

    stderr_buf.clearAndFree();
    try list_buckets.collectOutput(&list_buckets_stdout, &stderr_buf, 1 << 21);

    if (stderr_buf.items.len != 0) {
        std.log.err("\n{s}", .{stderr_buf.items});
    }
    switch (try list_buckets.wait()) {
        .Exited => |exit| if (exit != 0) return error.ListingExitWithFailureCode,
        .Signal => return error.ListingSignalled,
        .Stopped => return error.ListingStopped,
        .Unknown => return error.ListingUnknownExitState,
    }

    var bucket_list = std.ArrayList([]const u8).init(arena);
    defer bucket_list.deinit();

    var tokenizer = std.mem.tokenizeAny(u8, list_buckets_stdout.items, "\r\n");
    while (tokenizer.next()) |line| try bucket_list.append(line);

    const list_objects_argv = try std.mem.concat(arena, []const u8, &.{ &.{ "gcloud", "storage", "objects", "list", "--uri" }, bucket_list.items });
    defer arena.free(list_objects_argv);

    var list_objects = std.ChildProcess.init(list_objects_argv, arena);
    list_objects.stdout_behavior = .Pipe;
    list_objects.stderr_behavior = .Pipe;
    try list_objects.spawn();

    var list_objects_stdout = std.ArrayList(u8).init(arena);
    defer list_objects_stdout.deinit();

    try list_objects.spawn();

    stderr_buf.clearAndFree();
    try list_objects.collectOutput(&list_objects_stdout, &stderr_buf, 1 << 21);

    if (stderr_buf.items.len != 0) {
        std.log.err("\n{s}", .{stderr_buf.items});
    }
    switch (try list_objects.wait()) {
        .Exited => |exit| if (exit != 0) return error.ListingExitWithFailureCode,
        .Signal => return error.ListingSignalled,
        .Stopped => return error.ListingStopped,
        .Unknown => return error.ListingUnknownExitState,
    }

    var object_list = std.StringArrayHashMap(void).init(arena);
    defer object_list.deinit();
    defer for (object_list.keys()) |object_uri| arena.free(object_uri);

    tokenizer = std.mem.tokenizeAny(u8, list_objects_stdout.items, "\r\n");
    while (tokenizer.next()) |line| {
        errdefer |e| if (e == error.NotAnObjectUrl) {
            std.log.err("'{s}' is not formatted like an object URL", .{line});
        };

        const expected_prefix = "https://storage.googleapis.com/storage/v1/b/";
        if (!std.mem.startsWith(u8, line, expected_prefix)) return error.NotAnObjectUrl;
        const bucket_object_hashtag_uri = line[expected_prefix.len..];
        const bohu_hasthag_idx = std.mem.indexOfScalar(u8, bucket_object_hashtag_uri, '#') orelse bucket_object_hashtag_uri.len;
        const bucket_object = bucket_object_hashtag_uri[0..bohu_hasthag_idx];

        const slash_idx = std.mem.indexOfScalar(u8, bucket_object, '/') orelse return error.NotAnObjectUrl;
        if (!std.mem.startsWith(u8, bucket_object[slash_idx..], "/o/")) return error.NotAnObjectUrl;
        const object_name = try std.fmt.allocPrint(arena, "gs://{s}{s}", .{ bucket_object[0..slash_idx], bucket_object[slash_idx + "o/".len ..] });
        errdefer arena.free(object_name);

        const gop = try object_list.getOrPut(object_name);
        if (gop.found_existing) {
            arena.free(gop.key_ptr.*);
            gop.key_ptr.* = object_name;
        }
    }

    if (object_list.count() == 0) return;

    std.log.info("Deleting objects:\n{s}", .{list_objects_stdout.items});

    const delete_objs_argv = try std.mem.concat(arena, []const u8, &.{ &.{ "gcloud", "storage", "rm" }, object_list.keys() });
    defer arena.free(delete_objs_argv);

    var delete_objs = std.ChildProcess.init(delete_objs_argv, arena);
    try delete_objs.spawn();
    switch (try delete_objs.wait()) {
        .Exited => |exit| if (exit != 0) return error.DeletingExitWithFailureCode,
        .Signal => return error.DeletingSignalled,
        .Stopped => return error.DeletingStopped,
        .Unknown => return error.DeletingUnknownExitState,
    }
}
