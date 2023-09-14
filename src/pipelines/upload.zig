const chunk = @import("chunk.zig");
const erasure = @import("../erasure.zig");
const PipelineInitValues = @import("PipelineInitValues.zig");
const ServerInfo = @import("ServerInfo.zig");
const SharedQueue = @import("../shared_queue.zig").SharedQueue;

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

const util = @import("../util.zig");

pub const Ctx = struct {
    ptr: *anyopaque,
    actionFn: *const fn (ptr: *anyopaque, state: Action) void,
    data: Data,

    pub const Data = struct {
        file: std.fs.File,
        file_size: u64,
    };

    pub inline fn init(data: Data, ctx_ptr: anytype) Ctx {
        const Ptr = @TypeOf(ctx_ptr);
        const gen = struct {
            fn actionFn(erased_ptr: *anyopaque, action_data: Ctx.Action) void {
                const ptr: Ptr = @ptrCast(@alignCast(erased_ptr));
                switch (action_data) {
                    .update => |percentage| ptr.update(percentage),
                    .close => |close_data| ptr.close(close_data[0], close_data[1]),
                }
            }
        };
        return .{
            .ptr = ctx_ptr,
            .actionFn = gen.actionFn,
            .data = data,
        };
    }

    /// Informs the context of the percentage of progress.
    pub inline fn update(self: Ctx, percentage: u8) void {
        return self.action(.{ .update = percentage });
    }

    /// After returns, the `UploadCtx` will be destroyed,
    /// meaning either the file has been fully uploaded,
    /// or the process to upload the file has failed
    /// irrecoverably.
    /// Gives the file handle back to the inner context.
    /// If the upload was successful, returns the list of
    /// names the file was turned into.
    pub inline fn close(self: Ctx, digests: ?[]const [Sha256.digest_length]u8) void {
        return self.action(.{ .close = .{ self.data.file, digests } });
    }

    inline fn action(self: Ctx, data: Action) void {
        return self.actionFn(self.ptr, data);
    }
    pub const Action = union(enum) {
        /// percentage of progress
        update: u8,
        /// The upload context is being closed, so the file handle
        /// is returned. The context may store it elsewhere for
        /// further use, or simply close it.
        close: Close,

        const Close = struct { std.fs.File, ?[]const [Sha256.digest_length]u8 };
    };
};

pub fn PipeLine(comptime W: type) type {
    return struct {
        allocator: std.mem.Allocator,
        requests_buf: []std.http.Client.Request,
        server_info: ServerInfo,
        gc_prealloc: ?ServerInfo.GoogleCloud.PreAllocated,

        must_stop: std.atomic.Atomic(bool),
        queue_mtx: std.Thread.Mutex,
        queue: SharedQueue(Ctx),

        chunk_headers_buf_mtx: std.Thread.Mutex,
        chunk_headers_buf: std.MultiArrayList(ChunkHeaderInfo),
        chunk_buffer: []u8,

        ec: ErasureCoder,
        thread: std.Thread,
        const Self = @This();

        const ErasureCoder = erasure.Coder(W);
        const ChunkHeaderInfo = struct { header: chunk.Header, header_plus_blob_digest: [Sha256.digest_length]u8 };

        // TODO: should this use a more strict memory order?
        const must_stop_store_mo: std.builtin.AtomicOrder = .Monotonic;
        const must_stop_load_mo: std.builtin.AtomicOrder = .Monotonic;

        pub fn init(
            /// contents will be entirely oerwritten
            self: *Self,
            /// should be a thread-safe allocator
            allocator: std.mem.Allocator,
            values: PipelineInitValues,
        ) (std.mem.Allocator.Error || ErasureCoder.InitError || std.Thread.SpawnError)!void {
            assert(values.chunk_buffer != 0);
            assert(values.queue_capacity != 0);

            self.* = .{
                .allocator = allocator,
                .requests_buf = &.{},
                .server_info = values.server_info,
                .gc_prealloc = null,

                .must_stop = std.atomic.Atomic(bool).init(false),
                .queue_mtx = .{},
                .queue = undefined,

                .chunk_headers_buf_mtx = .{},
                .chunk_headers_buf = .{},
                .chunk_buffer = &.{},

                .ec = undefined,
                .thread = undefined,
            };

            self.requests_buf = try self.allocator.alloc(std.http.Client.Request, values.server_info.bucketCount());
            errdefer self.allocator.free(self.requests_buf);

            if (values.server_info.google_cloud) |gc| {
                self.gc_prealloc = try gc.preAllocated(self.allocator);
            }
            errdefer if (self.gc_prealloc) |pre_alloc| pre_alloc.deinit(self.allocator);

            self.queue = try SharedQueue(Ctx).initCapacity(&self.queue_mtx, self.allocator, values.queue_capacity);
            errdefer self.queue.deinit(self.allocator);

            self.chunk_buffer = try allocator.alloc(u8, values.chunk_buffer);
            errdefer allocator.free(self.chunk_buffer);

            self.ec = try ErasureCoder.init(self.allocator, @intCast(values.server_info.bucketCount()), values.server_info.shard_size);
            errdefer self.ec.deinit(self.allocator);

            self.thread = try std.Thread.spawn(.{ .allocator = self.allocator }, uploadPipeLineThread, .{self});
        }

        pub fn deinit(
            self: *Self,
            remaining_queue_fate: enum {
                finish_remaining_uploads,
                cancel_remaining_uploads,
            },
        ) void {
            self.must_stop.store(true, must_stop_store_mo);
            switch (remaining_queue_fate) {
                .finish_remaining_uploads => {},
                .cancel_remaining_uploads => self.queue.clearItems(),
            }
            self.thread.join();
            self.queue.deinit(self.allocator);

            self.chunk_headers_buf.deinit(self.allocator);
            self.allocator.free(self.chunk_buffer);

            self.ec.deinit(self.allocator);
            self.allocator.free(self.requests_buf);
            if (self.gc_prealloc) |pre_alloc| pre_alloc.deinit(self.allocator);
        }

        pub inline fn uploadFile(
            self: *Self,
            /// Should be a read-enabled file handle; if this call
            /// succeeds, the caller must leave the closing of the
            /// file handle to the `ctx_ptr`.
            file: std.fs.File,
            /// A struct/union/enum/opaque pointer implementing
            /// the `UploadCtx` interface.
            /// The pointer must outlive the function call, until
            /// its `close` callback is called.
            ctx_ptr: anytype,
            extra: struct {
                /// Pre-calculated size of the file; if `null`,
                /// the size will be determined during this function call.
                file_size: ?u64 = null,
            },
        ) (std.mem.Allocator.Error || std.fs.File.StatError)!void {
            self.queue.mutex.lock();
            defer self.queue.mutex.unlock();

            const file_size: u64 = file_size: {
                const file_size = extra.file_size orelse {
                    const stat = try file.stat();
                    break :file_size stat.size;
                };
                if (comptime @import("builtin").mode == .Debug) debug_check: {
                    const stat = try file.stat();
                    if (stat.size == file_size) break :debug_check;
                    const msg = util.boundedFmt(
                        "Given file size '{d}' differs from file size '{d}' obtained from stat",
                        .{ file_size, stat.size },
                        .{ std.math.maxInt(@TypeOf(file_size)), std.math.maxInt(@TypeOf(stat.size)) },
                    ) catch unreachable;
                    @panic(msg.constSlice());
                }
                break :file_size file_size;
            };

            {
                self.chunk_headers_buf_mtx.lock();
                defer self.chunk_headers_buf_mtx.unlock();
                try self.chunk_headers_buf.ensureTotalCapacity(self.allocator, chunk.countForFileSize(file_size));
            }

            const data = Ctx.Data{
                .file = file,
                .file_size = file_size,
            };
            _ = try self.queue.pushValueLocked(self.allocator, Ctx.init(data, ctx_ptr));
        }

        fn uploadPipeLineThread(upp: *Self) void {
            var client = std.http.Client{ .allocator = upp.allocator };
            defer client.deinit();

            while (true) {
                const up_ctx: Ctx = upp.queue.popValue() orelse {
                    if (upp.must_stop.load(must_stop_load_mo)) break;
                    std.atomic.spinLoopHint();
                    continue;
                };
                const up_data = up_ctx.data;
                const chunk_count = chunk.countForFileSize(up_data.file_size);
                defer {
                    upp.chunk_headers_buf_mtx.lock();
                    defer upp.chunk_headers_buf_mtx.unlock();
                    const digests = upp.chunk_headers_buf.items(.header_plus_blob_digest);
                    assert(digests.len <= chunk_count);
                    up_ctx.close(if (digests.len == chunk_count) digests else null);
                }

                init_chunk_headers: {
                    upp.chunk_headers_buf_mtx.lock();
                    defer upp.chunk_headers_buf_mtx.unlock();
                    upp.chunk_headers_buf.shrinkRetainingCapacity(0);

                    var hasher = chunk.chunkedSha256Hasher(up_data.file.reader(), chunk_count);
                    while (true) {
                        const maybe_chunk_sha = hasher.next(upp.chunk_buffer) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        const chunk_sha = maybe_chunk_sha orelse break;

                        if (upp.chunk_headers_buf.len != 0) {
                            const headers = upp.chunk_headers_buf.items(.header);
                            const prev = &headers[upp.chunk_headers_buf.len - 1];
                            prev.next_chunk_blob_digest = chunk_sha;
                        }
                        // should have capacity reserved during `uploadFile`
                        upp.chunk_headers_buf.appendAssumeCapacity(.{
                            .header = chunk.Header{
                                .next_chunk_blob_digest = undefined,
                                .current_chunk_digest = chunk_sha,
                                .full_file_digest = null,
                            },
                            .header_plus_blob_digest = undefined,
                        });
                    }

                    const headers = upp.chunk_headers_buf.items(.header);
                    const first = &headers[0];
                    first.full_file_digest = hasher.fullHash().?;

                    const last = &headers[upp.chunk_headers_buf.len - 1];
                    last.next_chunk_blob_digest = first.current_chunk_digest;
                    break :init_chunk_headers;
                }

                var bytes_uploaded: u64 = 0;

                for (0..chunk_count) |chunk_idx_uncasted| {
                    const chunk_idx: chunk.Count = @intCast(chunk_idx_uncasted);
                    const offset = chunk.startOffset(chunk_idx);

                    upp.chunk_headers_buf_mtx.lock();
                    const header: chunk.Header = upp.chunk_headers_buf.items(.header)[chunk_idx];
                    upp.chunk_headers_buf_mtx.unlock();

                    const chunk_name: [Sha256.digest_length]u8 = blk: {
                        const Fifo = std.fifo.LinearFifo(u8, .Slice);
                        var fifo: Fifo = Fifo.init(upp.chunk_buffer);

                        up_data.file.seekTo(offset) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        const chunk_name = header.calcName(up_data.file.reader(), &fifo) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };

                        upp.chunk_headers_buf_mtx.lock();
                        upp.chunk_headers_buf.items(.header_plus_blob_digest)[chunk_idx] = chunk_name;
                        upp.chunk_headers_buf_mtx.unlock();
                        break :blk chunk_name;
                    };

                    var requests = util.BoundedBufferArray(std.http.Client.Request){ .buffer = upp.requests_buf };
                    defer for (requests.slice()) |*req| req.deinit();

                    if (upp.server_info.google_cloud) |gc| {
                        const gc_prealloc = upp.gc_prealloc.?;

                        var iter = gc_prealloc.bucketObjectUriIterator(gc, &chunk_name);
                        while (iter.next()) |uri_str| {
                            const uri = std.Uri.parse(uri_str) catch unreachable;
                            const req = client.request(.PUT, uri, gc_prealloc.headers, .{}) catch |err| switch (err) {
                                error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                                inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                            };
                            requests.appendAssumingCapacity(req);
                        }
                    }

                    for (requests.slice()) |*req| {
                        req.start() catch |err| @panic(switch (err) {
                            inline else => |e| "Decide how to handle " ++ @errorName(e),
                        });
                        chunk.writeHeader(req.writer(), &header) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                    }

                    const WritersCtx = struct {
                        requests: []std.http.Client.Request,
                        up_ctx: Ctx,
                        bytes_uploaded: *u64,
                        upload_size: u64,

                        const WriterCtx = struct {
                            inner: Inner,
                            up_ctx: Ctx,
                            bytes_uploaded: *u64,
                            upload_size: u64,

                            const Inner = std.http.Client.Request.Writer;
                            const Error = Inner.Error;
                            fn write(self: @This(), bytes: []const u8) Error!usize {
                                const written = try self.inner.write(bytes);
                                self.bytes_uploaded.* += written;
                                self.up_ctx.update(@intCast((self.bytes_uploaded.* * 100) / self.upload_size));
                                return written;
                            }
                        };
                        pub inline fn getWriter(ctx: @This(), writer_idx: u7) std.io.Writer(WriterCtx, WriterCtx.Error, WriterCtx.write) {
                            return .{ .context = .{
                                .inner = ctx.requests[writer_idx].writer(),
                                .up_ctx = ctx.up_ctx,
                                .bytes_uploaded = ctx.bytes_uploaded,
                                .upload_size = ctx.upload_size,
                            } };
                        }
                    };

                    const writers_ctx = WritersCtx{
                        .requests = requests.slice(),
                        .up_ctx = up_ctx,
                        .bytes_uploaded = &bytes_uploaded,
                        .upload_size = size: {
                            const shard_size = @as(u64, up_data.file_size) / upp.ec.shardsRequired();
                            break :size shard_size * upp.ec.shardCount();
                        },
                    };

                    up_data.file.seekTo(0) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                    var buffered = std.io.bufferedReader(up_data.file.reader());
                    _ = upp.ec.encodeCtx(buffered.reader(), writers_ctx) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };

                    for (requests.slice()) |*req| req.finish() catch |err| @panic(switch (err) {
                        inline else => |e| "Decide how to handle " ++ @errorName(e),
                    });

                    for (@as([]std.http.Client.Request, requests.slice())) |*req| {
                        req.wait() catch |err| switch (err) {
                            error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                    }
                    up_ctx.update(100);
                }
            }
        }
    };
}
