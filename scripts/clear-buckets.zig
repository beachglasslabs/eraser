//! Used to clear all the buckets in google cloud
//! Should *ONLY* be used during testing, deletes
//! *ALL* objects indiscriminately.
//! Calls the system command 'gcloud', once to list
//! the buckets, a second time to list the objects,
//! and a third time to delete them.
const std = @import("std");

pub fn main() !void {
    var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const gc_flag: ?[]const u8 = std.process.getEnvVarOwned(allocator, "ZIG_GOOGLE_CLOUD") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => |e| return e,
    };
    defer allocator.free(gc_flag orelse &[_]u8{});

    if (std.mem.trim(u8, gc_flag orelse "", &std.ascii.whitespace).len != 0) {
        std.log.err("Expected flag environment variable, but \"{s}\"=\"{s}\"", .{ "ZIG_GOOGLE_CLOUD", gc_flag.? });
        return error.NonFlagGoogleCloudFlag;
    }

    const aws_profile_name: ?[]const u8 = std.process.getEnvVarOwned(allocator, "ZIG_AWS_PROFILE_NAME") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => |e| return e,
    };
    defer allocator.free(aws_profile_name orelse &[_]u8{});

    if (gc_flag != null) try deleteGoogleCloudObjects(allocator);
    if (aws_profile_name) |profile_name| try deleteAwsObjects(allocator, profile_name);
}

fn deleteGoogleCloudObjects(allocator: std.mem.Allocator) !void {
    var list_buckets = std.ChildProcess.init(&.{ "gcloud", "storage", "ls" }, allocator);
    list_buckets.stdout_behavior = .Pipe;
    list_buckets.stderr_behavior = .Pipe;
    try list_buckets.spawn();

    var stderr_buf = std.ArrayList(u8).init(allocator);
    defer stderr_buf.deinit();

    var list_buckets_stdout = std.ArrayList(u8).init(allocator);
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

    var bucket_list = std.ArrayList([]const u8).init(allocator);
    defer bucket_list.deinit();

    var tokenizer = std.mem.tokenizeAny(u8, list_buckets_stdout.items, "\r\n");
    while (tokenizer.next()) |line| try bucket_list.append(line);

    const list_objects_argv = try std.mem.concat(allocator, []const u8, &.{ &.{ "gcloud", "storage", "objects", "list", "--uri" }, bucket_list.items });
    defer allocator.free(list_objects_argv);

    var list_objects = std.ChildProcess.init(list_objects_argv, allocator);
    list_objects.stdout_behavior = .Pipe;
    list_objects.stderr_behavior = .Pipe;
    try list_objects.spawn();

    var list_objects_stdout = std.ArrayList(u8).init(allocator);
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

    var object_list = std.StringArrayHashMap(void).init(allocator);
    defer object_list.deinit();
    defer for (object_list.keys()) |object_uri| allocator.free(object_uri);

    tokenizer = std.mem.tokenizeAny(u8, list_objects_stdout.items, "\r\n");
    while (tokenizer.next()) |line| {
        const expected_prefix = "https://storage.googleapis.com/storage/v1/b/";
        if (!std.mem.startsWith(u8, line, expected_prefix)) return error.NotAnObjectUrl;
        const bucket_object_hashtag_uri = line[expected_prefix.len..];
        const bohu_hasthag_idx = std.mem.indexOfScalar(u8, bucket_object_hashtag_uri, '#') orelse bucket_object_hashtag_uri.len;
        const bucket_object = bucket_object_hashtag_uri[0..bohu_hasthag_idx];

        const slash_idx = std.mem.indexOfScalar(u8, bucket_object, '/') orelse return error.NotAnObjectUrl;
        if (!std.mem.startsWith(u8, bucket_object[slash_idx..], "/o/")) return error.NotAnObjectUrl;
        const object_name = try std.fmt.allocPrint(allocator, "gs://{s}{s}", .{ bucket_object[0..slash_idx], bucket_object[slash_idx + "o/".len ..] });
        errdefer allocator.free(object_name);

        const gop = try object_list.getOrPut(object_name);
        if (gop.found_existing) {
            allocator.free(gop.key_ptr.*);
            gop.key_ptr.* = object_name;
        }
    }

    if (object_list.count() == 0) return;

    const delete_objs_argv = try std.mem.concat(allocator, []const u8, &.{ &.{ "gcloud", "storage", "rm" }, object_list.keys() });
    defer allocator.free(delete_objs_argv);

    var delete_objs = std.ChildProcess.init(delete_objs_argv, allocator);
    try delete_objs.spawn();
    switch (try delete_objs.wait()) {
        .Exited => |exit| if (exit != 0) return error.DeletingExitWithFailureCode,
        .Signal => return error.DeletingSignalled,
        .Stopped => return error.DeletingStopped,
        .Unknown => return error.DeletingUnknownExitState,
    }
}

fn deleteAwsObjects(allocator: std.mem.Allocator, profile_name: []const u8) !void {
    var list_buckets = std.ChildProcess.init(&.{ "aws", "s3", "ls", "--profile", profile_name }, allocator);
    list_buckets.stdout_behavior = .Pipe;
    list_buckets.stderr_behavior = .Pipe;
    try list_buckets.spawn();

    var stderr_buf = std.ArrayList(u8).init(allocator);
    defer stderr_buf.deinit();

    var list_buckets_stdout = std.ArrayList(u8).init(allocator);
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

    var bucket_list = std.ArrayList([]const u8).init(allocator);
    defer bucket_list.deinit();

    var tokenizer = std.mem.tokenizeAny(u8, list_buckets_stdout.items, "\r\n");
    while (tokenizer.next()) |line| {
        var component_iter = std.mem.tokenizeScalar(u8, line, ' ');
        _ = component_iter.next() orelse return error.MissingDate;
        _ = component_iter.next() orelse return error.MissingTime;
        const bucket_name = component_iter.next() orelse return error.MissingBucketName;
        try bucket_list.append(bucket_name);
    }

    for (bucket_list.items) |bucket_name| {
        var list_objects = std.ChildProcess.init(&.{ "aws", "s3", "ls", bucket_name, "--profile", profile_name }, allocator);
        list_objects.stdout_behavior = .Pipe;
        list_objects.stderr_behavior = .Pipe;
        try list_objects.spawn();

        var list_objects_stdout = std.ArrayList(u8).init(allocator);
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

        tokenizer = std.mem.tokenizeAny(u8, list_objects_stdout.items, "\r\n");

        var object_path_buf = std.ArrayList(u8).init(allocator);
        defer object_path_buf.deinit();

        while (tokenizer.next()) |line| {
            var component_iter = std.mem.tokenizeScalar(u8, line, ' ');
            _ = component_iter.next() orelse return error.MissingDate;
            _ = component_iter.next() orelse return error.MissingTime;
            _ = component_iter.next() orelse return error.MissingSize;
            const object_name = component_iter.next() orelse return error.MissingBucketName;

            object_path_buf.clearRetainingCapacity();
            try object_path_buf.writer().print("s3://{s}/{s}", .{ bucket_name, object_name });
            const object_path = object_path_buf.items;

            var delete_objs = std.ChildProcess.init(&.{ "aws", "s3", "rm", object_path, "--profile", profile_name }, allocator);
            try delete_objs.spawn();
            switch (try delete_objs.wait()) {
                .Exited => |exit| if (exit != 0) return error.DeletingExitWithFailureCode,
                .Signal => return error.DeletingSignalled,
                .Stopped => return error.DeletingStopped,
                .Unknown => return error.DeletingUnknownExitState,
            }
        }
    }
}
