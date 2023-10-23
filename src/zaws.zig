const std = @import("std");
const assert = std.debug.assert;

const util = @import("util.zig");

pub const c = @cImport({
    @cInclude("aws/auth/credentials.h");
    @cInclude("aws/common/condition_variable.h");
    @cInclude("aws/common/mutex.h");
    @cInclude("aws/io/channel_bootstrap.h");
    @cInclude("aws/io/event_loop.h");
    @cInclude("aws/io/logging.h");
    @cInclude("aws/io/uri.h");
    @cInclude("aws/s3/s3_client.h");
    @cInclude("aws/s3/s3.h");

    // implemented by us to get around the API's use of bitfields
    @cInclude("zaws/zaws.h");
});

pub inline fn createSigningConfig(params: c.zig_aws_signing_config_aws_wrapper) c.zig_aws_signing_config_aws_bytes {
    var result: c.zig_aws_signing_config_aws_bytes = undefined;
    c.zig_aws_s3_init_signing_config(&result, &params);
    return result;
}

pub inline fn byteCursorToSlice(bc: c.aws_byte_cursor) ?[]u8 {
    const ptr: [*]u8 = bc.ptr orelse return null;
    return ptr[0..bc.len];
}
pub inline fn byteCursorFromSlice(slice: ?[]u8) c.aws_byte_cursor {
    return .{
        .len = if (slice) |s| s.len else 0,
        .ptr = if (slice) |s| s.ptr else null,
    };
}

/// Returns an aws allocator wrapping the given zig allocator.
pub fn awsAllocator(
    /// Must outlive the returned `c.aws_allocator`.
    allocator: *const std.mem.Allocator,
) c.aws_allocator {
    const gen = struct {
        const alignment = 16;

        const Metadata = extern struct {
            size: usize,

            const padded_size = std.mem.alignForward(usize, @sizeOf(Metadata), alignment);
        };

        fn acquire(aws_allocator: [*c]c.aws_allocator, size: usize) callconv(.C) ?*anyopaque {
            const ally: *const std.mem.Allocator = @alignCast(@ptrCast(@as(?*const c.aws_allocator, aws_allocator).?.impl.?));

            const aligned_len = Metadata.padded_size + size;
            const allocation = ally.alignedAlloc(u8, alignment, aligned_len) catch return null;
            std.mem.bytesAsValue(Metadata, allocation[0..@sizeOf(Metadata)]).* = .{
                .size = size,
            };
            return allocation[Metadata.padded_size..].ptr;
        }

        fn release(aws_allocator: [*c]c.aws_allocator, maybe_ptr: ?*anyopaque) callconv(.C) void {
            const ally: *const std.mem.Allocator = @alignCast(@ptrCast(@as(?*const c.aws_allocator, aws_allocator).?.impl.?));

            const ptr: [*]align(16) u8 = @alignCast(@ptrCast(maybe_ptr orelse return));
            const base_ptr: [*]align(16) u8 = ptr - Metadata.padded_size;

            const metadata = std.mem.bytesToValue(Metadata, base_ptr[0..@sizeOf(Metadata)]);
            const allocation = base_ptr[0 .. Metadata.padded_size + metadata.size];
            ally.free(allocation);
        }

        fn realloc(aws_allocator: [*c]c.aws_allocator, maybe_ptr: ?*anyopaque, old_size: usize, new_size: usize) callconv(.C) ?*anyopaque {
            const ally: *const std.mem.Allocator = @alignCast(@ptrCast(@as(?*const c.aws_allocator, aws_allocator).?.impl.?));
            const ptr: [*]align(16) u8 = @alignCast(@ptrCast(maybe_ptr orelse {
                assert(old_size == 0);
                return acquire(aws_allocator, new_size);
            }));

            const base_ptr: [*]align(16) u8 = ptr - Metadata.padded_size;
            const old_metadata = std.mem.bytesToValue(Metadata, base_ptr[0..@sizeOf(Metadata)]);
            assert(old_metadata.size == old_size);
            if (new_size == 0) {
                release(aws_allocator, maybe_ptr);
                return null;
            }

            const reallocated = ally.realloc(base_ptr[0 .. Metadata.padded_size + old_size], Metadata.padded_size + new_size) catch return null;
            const new_metadata = std.mem.bytesAsValue(Metadata, reallocated[0..@sizeOf(Metadata)]);
            new_metadata.* = .{
                .size = new_size,
            };
            return reallocated[Metadata.padded_size..].ptr;
        }

        fn calloc(aws_allocator: [*c]c.aws_allocator, num: usize, val_size: usize) callconv(.C) ?*anyopaque {
            const ally: *const std.mem.Allocator = @alignCast(@ptrCast(@as(?*const c.aws_allocator, aws_allocator).?.impl.?));
            const size = num * val_size;

            const aligned_len = Metadata.padded_size + size;
            const allocation = ally.alignedAlloc(u8, alignment, aligned_len) catch return null;
            std.mem.bytesAsValue(Metadata, allocation[0..@sizeOf(Metadata)]).* = .{
                .size = size,
            };

            const result = allocation[Metadata.padded_size..];
            @memset(result, 0);

            return result.ptr;
        }
    };

    return c.aws_allocator{
        .mem_acquire = gen.acquire,
        .mem_release = gen.release,
        .mem_realloc = gen.realloc,
        .mem_calloc = gen.calloc,
        .impl = @constCast(allocator),
    };
}
