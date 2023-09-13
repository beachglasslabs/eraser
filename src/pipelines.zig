const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const util = @import("util.zig");

const erasure = @import("erasure.zig");
pub const SensitiveBytes = @import("SensitiveBytes.zig");
pub const SharedQueue = @import("shared_queue.zig").SharedQueue;

pub const chunk_size: comptime_int = 15 * bytes_per_megabyte;
const bytes_per_megabyte = 10_000_000;

const ChunkCount = std.math.IntFittingRange(1, std.math.maxInt(u64) / chunk_size);
inline fn chunksForFileSize(size: u64) std.math.IntFittingRange(1, std.math.maxInt(u64) / chunk_size) {
    return @intCast(size / chunk_size + 1);
}
inline fn chunkStartOffset(chunk_idx: ChunkCount) u64 {
    return @as(u64, chunk_idx) * chunk_size;
}

pub const PipelineInitValues = struct {
    chunk_buffer: usize = 150_000,
    queue_capacity: usize,
    server_info: ServerInfo,
};

pub const ServerInfo = struct {
    shard_size: u7,
    google_cloud: ?GoogleCloud = null,

    pub const GoogleCloud = struct {
        auth_token: SensitiveBytes,
        bucket_names: []const []const u8,

        const authorization_value_fmt = "Bearer {[auth_token]s}";
        const bucket_object_uri_fmt = "https://storage.googleapis.com/{[bucket]s}/{[object]s}";

        fn preAllocated(gc: GoogleCloud, allocator: std.mem.Allocator) std.mem.Allocator.Error!PreAllocated {
            var full_size: usize = 0;
            full_size += std.fmt.count(authorization_value_fmt, .{ .auth_token = gc.auth_token.getSensitiveSlice() });

            for (gc.bucket_names) |bucket_name| {
                const max_digest_str: []const u8 = comptime &digestBytesToString("\xff" ** Sha256.digest_length);
                full_size += std.fmt.count(bucket_object_uri_fmt, .{
                    .bucket = bucket_name,
                    .object = max_digest_str,
                });
            }

            const full_buf_alloc = try allocator.alloc(u8, full_size);
            errdefer allocator.free(full_buf_alloc);

            const authorization_value = std.fmt.bufPrint(full_buf_alloc, authorization_value_fmt, .{ .auth_token = gc.auth_token.getSensitiveSlice() }) catch unreachable;
            const bucket_uris_buf = full_buf_alloc[authorization_value.len..];

            var headers = std.http.Headers.init(allocator);
            errdefer headers.deinit();
            headers.owned = false;

            try headers.append("Authorization", authorization_value);
            try headers.append("Transfer-Encoding", "chunked");

            return .{
                .full_buf_alloc = full_buf_alloc,
                .authorization_value = authorization_value,
                .bucket_uris_buf = bucket_uris_buf,
                .headers = headers,
            };
        }

        const PreAllocated = struct {
            full_buf_alloc: []u8,
            authorization_value: []const u8,
            bucket_uris_buf: []u8,
            headers: std.http.Headers,

            pub fn deinit(pre_allocated: PreAllocated, allocator: std.mem.Allocator) void {
                allocator.free(pre_allocated.full_buf_alloc);

                var headers_copy = pre_allocated.headers;
                headers_copy.allocator = allocator;
                headers_copy.deinit();
            }

            /// The strings obtained from the returned iterator are valid until the next call to this function.
            pub fn bucketObjectUriIterator(self: PreAllocated, gc: GoogleCloud, object: *const [Sha256.digest_length]u8) BucketObjectUriIterator {
                return .{
                    .bucket_names = gc.bucket_names,
                    .bytes = .{ .buffer = self.bucket_uris_buf },
                    .object = object,
                };
            }

            const BucketObjectUriIterator = struct {
                index: usize = 0,
                bucket_names: []const []const u8,
                bytes: util.BoundedBufferArray(u8),
                object: *const [Sha256.digest_length]u8,

                /// Each string returned is a unique slice which does not overlap with any previously returned slice.
                pub fn next(iter: *BucketObjectUriIterator) ?[]const u8 {
                    if (iter.index == iter.bucket_names.len) return null;
                    const bucket = iter.bucket_names[iter.index];
                    iter.index += 1;

                    const start = iter.bytes.len;
                    iter.bytes.writer().print(bucket_object_uri_fmt, .{
                        .bucket = bucket,
                        .object = &digestBytesToString(iter.object),
                    }) catch |err| switch (err) {
                        error.Overflow => unreachable,
                    };
                    const end = iter.bytes.len;
                    return iter.bytes.slice()[start..end];
                }
            };
        };
    };

    inline fn bucketCount(server_info: ServerInfo) usize {
        var result: usize = 0;
        if (server_info.google_cloud) |gcloud| {
            result += gcloud.bucket_names.len;
        }
        return result;
    }
};

pub const UploadCtx = struct {
    ptr: *anyopaque,
    actionFn: *const fn (ptr: *anyopaque, state: Action) void,
    data: Data,

    pub const Data = struct {
        file: std.fs.File,
        file_size: u64,
    };

    pub inline fn init(data: Data, ctx_ptr: anytype) UploadCtx {
        const Ptr = @TypeOf(ctx_ptr);
        const gen = struct {
            fn actionFn(erased_ptr: *anyopaque, action_data: UploadCtx.Action) void {
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
    pub inline fn update(self: UploadCtx, percentage: u8) void {
        return self.action(.{ .update = percentage });
    }

    /// After returns, the `UploadCtx` will be destroyed,
    /// meaning either the file has been fully uploaded,
    /// or the process to upload the file has failed
    /// irrecoverably.
    /// Gives the file handle back to the inner context.
    /// If the upload was successful, returns the list of
    /// names the file was turned into.
    pub inline fn close(self: UploadCtx, digests: ?[]const [Sha256.digest_length]u8) void {
        return self.action(.{ .close = .{ self.data.file, digests } });
    }

    inline fn action(self: UploadCtx, data: Action) void {
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

pub fn UploadPipeLine(comptime W: type) type {
    return struct {
        allocator: std.mem.Allocator,
        requests_buf: []std.http.Client.Request,
        server_info: ServerInfo,
        gc_prealloc: ?ServerInfo.GoogleCloud.PreAllocated,

        must_stop: std.atomic.Atomic(bool),
        queue_mtx: std.Thread.Mutex,
        queue: SharedQueue(UploadCtx),

        chunk_headers_buf_mtx: std.Thread.Mutex,
        chunk_headers_buf: std.MultiArrayList(ChunkHeaderInfo),
        chunk_buffer: []u8,

        ec: ErasureCoder,
        thread: std.Thread,
        const Self = @This();

        const ErasureCoder = erasure.Coder(W);
        const ChunkHeaderInfo = struct { header: ChunkHeader, header_plus_blob_digest: [Sha256.digest_length]u8 };

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

            self.queue = try SharedQueue(UploadCtx).initCapacity(&self.queue_mtx, self.allocator, values.queue_capacity);
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
                try self.chunk_headers_buf.ensureTotalCapacity(self.allocator, chunksForFileSize(file_size));
            }

            const data = UploadCtx.Data{
                .file = file,
                .file_size = file_size,
            };
            _ = try self.queue.pushValueLocked(self.allocator, UploadCtx.init(data, ctx_ptr));
        }

        fn uploadPipeLineThread(upp: *Self) void {
            var client = std.http.Client{ .allocator = upp.allocator };
            defer client.deinit();

            while (true) {
                const up_ctx: UploadCtx = upp.queue.popValue() orelse {
                    if (upp.must_stop.load(must_stop_load_mo)) break;
                    std.atomic.spinLoopHint();
                    continue;
                };
                const up_data = up_ctx.data;
                const chunk_count = chunksForFileSize(up_data.file_size);
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

                    var hasher = chunkedSha256Hasher(up_data.file.reader(), chunk_count);
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
                            .header = ChunkHeader{
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
                    const chunk_idx: ChunkCount = @intCast(chunk_idx_uncasted);
                    const offset = chunkStartOffset(chunk_idx);

                    upp.chunk_headers_buf_mtx.lock();
                    const header: ChunkHeader = upp.chunk_headers_buf.items(.header)[chunk_idx];
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
                        up_data.file.seekTo(0) catch |err| switch (err) {
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
                        writeChunkHeader(req.writer(), &header) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                    }

                    const WritersCtx = struct {
                        requests: []std.http.Client.Request,
                        up_ctx: UploadCtx,
                        bytes_uploaded: *u64,
                        upload_size: u64,

                        const WriterCtx = struct {
                            inner: Inner,
                            up_ctx: UploadCtx,
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

pub const DownloadCtx = struct {
    ptr: *anyopaque,
    actionFn: *const fn (ptr: *anyopaque, state: Action) void,
    data: Data,

    pub const Data = struct {
        chunk_names: []const [Sha256.digest_length]u8,
    };

    pub inline fn init(data: Data, ctx_ptr: anytype) DownloadCtx {
        const Ptr = @TypeOf(ctx_ptr);
        const gen = struct {
            fn actionFn(erased_ptr: *anyopaque, action_data: DownloadCtx.Action) void {
                const ptr: Ptr = @ptrCast(@alignCast(erased_ptr));
                switch (action_data) {
                    .update => |percentage| ptr.update(percentage),
                    .close => ptr.close(),
                }
            }
        };
        return .{
            .ptr = ctx_ptr,
            .actionFn = gen.actionFn,
            .data = data,
        };
    }

    pub inline fn update(self: DownloadCtx, percentage: u8) void {
        return self.action(.{ .update = percentage });
    }

    pub inline fn close(self: DownloadCtx) void {
        return self.action(.{ .close = {} });
    }

    inline fn action(self: DownloadCtx, data: Action) void {
        return self.actionFn(self.ptr, data);
    }

    pub const Action = union(enum) {
        /// percentage of progress
        update: u8,
        close,
    };
};
pub fn DownloadPipeLine(comptime W: type) type {
    return struct {
        allocator: std.mem.Allocator,
        requests_buf: []std.http.Client.Request,
        server_info: ServerInfo,
        gc_prealloc: ?ServerInfo.GoogleCloud.PreAllocated,

        must_stop: std.atomic.Atomic(bool),
        queue_mtx: std.Thread.Mutex,
        queue: SharedQueue(DownloadCtx),

        chunk_headers_buf_mtx: std.Thread.Mutex,
        chunk_headers_buf: std.ArrayListUnmanaged(ChunkHeader),
        chunk_buffer: []u8,

        random: std.rand.Random,
        ec: ErasureCoder,
        thread: std.Thread,
        const Self = @This();

        const ErasureCoder = erasure.Coder(W);

        // TODO: should this use a more strict memory order?
        const must_stop_store_mo: std.builtin.AtomicOrder = .Monotonic;
        const must_stop_load_mo: std.builtin.AtomicOrder = .Monotonic;

        pub fn init(
            /// contents will be entirely oerwritten
            self: *Self,
            /// should be a thread-safe allocator
            allocator: std.mem.Allocator,
            /// should be thread-safe Pseudo-RNG
            random: std.rand.Random,
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

                .random = random,
                .ec = undefined,
                .thread = undefined,
            };

            self.requests_buf = try self.allocator.alloc(std.http.Client.Request, values.server_info.bucketCount());
            errdefer self.allocator.free(self.requests_buf);

            if (values.server_info.google_cloud) |gc| {
                self.gc_prealloc = try gc.preAllocated(self.allocator);
            }
            errdefer if (self.gc_prealloc) |pre_alloc| pre_alloc.deinit(self.allocator);

            self.queue = try SharedQueue(DownloadCtx).initCapacity(&self.queue_mtx, self.allocator, values.queue_capacity);
            errdefer self.queue.deinit(self.allocator);

            self.chunk_buffer = try allocator.alloc(u8, values.chunk_buffer);
            errdefer allocator.free(self.chunk_buffer);

            self.ec = try ErasureCoder.init(self.allocator, @intCast(values.server_info.bucketCount()), values.server_info.shard_size);
            errdefer self.ec.deinit(self.allocator);

            self.thread = try std.Thread.spawn(.{ .allocator = self.allocator }, downloadPipeLineThread, .{self});
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

        pub fn downloadFile(
            self: *Self,
            digests: []const [Sha256.digest_length]u8,
            ctx_ptr: anytype,
        ) !void {
            {
                self.chunk_headers_buf_mtx.lock();
                defer self.chunk_headers_buf_mtx.unlock();
                try self.chunk_headers_buf.ensureTotalCapacity(self.allocator, digests.len);
            }
            const data = DownloadCtx.Data{
                .chunk_names = digests,
            };
            _ = try self.queue.pushValue(self.allocator, DownloadCtx.init(data, ctx_ptr));
        }

        fn downloadPipeLineThread(dpp: *Self) void {
            var client = std.http.Client{ .allocator = dpp.allocator };
            defer client.deinit();

            while (true) {
                const down_ctx: DownloadCtx = dpp.queue.popValue() orelse {
                    if (dpp.must_stop.load(must_stop_load_mo)) break;
                    std.atomic.spinLoopHint();
                    continue;
                };
                defer down_ctx.close();

                const excluded_index_set = erasure.sampleIndexSet(
                    dpp.random,
                    dpp.ec.shardCount(),
                    dpp.ec.shardCount() - dpp.ec.shardsRequired(),
                );
                var current_index: u8 = 0;

                var maybe_file: ?std.fs.File = null;
                defer if (maybe_file) |file| file.close();

                for (down_ctx.data.chunk_names) |chunk_name| {
                    var requests = util.BoundedBufferArray(std.http.Client.Request){ .buffer = dpp.requests_buf };
                    defer for (requests.slice()) |*req| req.deinit();

                    if (dpp.server_info.google_cloud) |gc| {
                        const gc_prealloc = dpp.gc_prealloc.?;

                        var iter = gc_prealloc.bucketObjectUriIterator(gc, &chunk_name);

                        while (iter.next()) |uri_str| : (current_index += 1) {
                            if (excluded_index_set.isSet(current_index)) continue;

                            const uri = std.Uri.parse(uri_str) catch unreachable;
                            const req = client.request(.GET, uri, gc_prealloc.headers, .{}) catch |err| switch (err) {
                                error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                                inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                            };
                            requests.appendAssumingCapacity(req);
                        }
                    }

                    // NOTE: this should be safe from any race condition, because
                    // the only other place where this field is modified is in
                    // `downloadFile`, where it calls `ensureTotalCapacity`, which
                    // should not modify the `items.len` field at all, which is
                    // all this function does.
                    dpp.chunk_headers_buf.clearRetainingCapacity();

                    for (requests.slice()) |*req| {
                        req.start() catch |err| @panic(switch (err) {
                            inline else => |e| "Decide how to handle " ++ @errorName(e),
                        });
                        req.finish() catch |err| @panic(switch (err) {
                            inline else => |e| "Decide how to handle " ++ @errorName(e),
                        });
                        req.wait() catch |err| switch (err) {
                            error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };

                        const header = readChunkHeader(req.reader()) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };

                        dpp.chunk_headers_buf_mtx.lock();
                        defer dpp.chunk_headers_buf_mtx.unlock();
                        dpp.chunk_headers_buf.appendAssumeCapacity(header);
                    }

                    const ReadersCtx = struct {
                        requests: []std.http.Client.Request,
                        down_ctx: DownloadCtx,

                        const ReaderCtx = struct {
                            inner: Inner,
                            down_ctx: DownloadCtx,

                            const Inner = std.http.Client.Request.Reader;
                            const Error = Inner.Error;
                            fn read(self: @This(), buf: []u8) Error!usize {
                                const result = try self.inner.read(buf);
                                return result;
                            }
                        };
                        pub inline fn getReader(ctx: @This(), reader_idx: u7) std.io.Reader(ReaderCtx, ReaderCtx.Error, ReaderCtx.read) {
                            return .{ .context = .{
                                .inner = ctx.requests[reader_idx].reader(),
                                .down_ctx = ctx.down_ctx,
                            } };
                        }
                    };
                    const readers_ctx = ReadersCtx{
                        .requests = requests.slice(),
                        .down_ctx = down_ctx,
                    };

                    const file = maybe_file orelse blk: {
                        const file = std.fs.cwd().createFile("decoded", .{}) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        maybe_file = file;
                        break :blk file;
                    };

                    var buffered = std.io.bufferedWriter(file.writer());
                    _ = dpp.ec.decodeCtx(excluded_index_set, buffered.writer(), readers_ctx) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                    buffered.flush() catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                }
            }
        }
    };
}

pub inline fn chunkedSha256Hasher(reader: anytype, chunk_count: ChunkCount) ChunkedSha256Hasher(@TypeOf(reader)) {
    return .{
        .reader = reader,
        .chunk_count = chunk_count,
        .chunk_size = chunk_size,
    };
}
pub fn ChunkedSha256Hasher(comptime ReaderType: type) type {
    return struct {
        reader: ReaderType,
        chunk_count: ChunkCount,
        comptime chunk_size: u64 = chunk_size,

        full_hasher: Sha256 = Sha256.init(.{}),
        chunk_hasher: Sha256 = Sha256.init(.{}),
        chunk_byte_count: u64 = 0,
        chunks_hashed: ChunkCount = 0,
        const Self = @This();

        pub fn fullHash(self: *Self) ?[Sha256.digest_length]u8 {
            if (self.chunks_hashed < self.chunk_count) return null;
            assert(self.chunks_hashed == self.chunk_count);
            return self.full_hasher.finalResult();
        }

        pub fn next(
            self: *Self,
            /// Buffer used to read into from the reader.
            buf: []u8,
        ) !?[Sha256.digest_length]u8 {
            assert(buf.len != 0);
            while (true) {
                const byte_count = try self.reader.readAll(buf);

                if (byte_count == 0) {
                    if (self.chunks_hashed == self.chunk_count) break;
                    defer self.chunks_hashed += 1;
                    if (self.chunks_hashed + 1 < self.chunk_count) @panic(
                        "Reader returned fewer chunks than expected",
                    );
                    assert(self.chunks_hashed + 1 == self.chunk_count);
                    return self.chunk_hasher.finalResult();
                } else if (self.chunks_hashed >= self.chunk_count) {
                    @panic("Reader returned more chunks than expected");
                }

                self.full_hasher.update(buf[0..byte_count]);
                self.chunk_byte_count += byte_count;
                if (self.chunk_byte_count < self.chunk_size) {
                    self.chunk_hasher.update(buf[0..byte_count]);
                    continue;
                }

                const amt = chunk_size - (self.chunk_byte_count - byte_count);
                self.chunk_byte_count -= chunk_size;

                if (amt != 0) {
                    self.chunk_hasher.update(buf[0..amt]);
                    std.mem.copyForwards(u8, buf, buf[amt..]);
                }

                const chunk_sha = self.chunk_hasher.finalResult();
                self.chunk_hasher = Sha256.init(.{});

                const remaining_bytes = byte_count - amt;
                if (remaining_bytes != 0) {
                    self.chunk_hasher.update(buf[0..remaining_bytes]);
                }
                self.chunks_hashed += 1;
                return chunk_sha;
            }
            return null;
        }
    };
}

pub const ChunkHeaderVersion = extern struct {
    major: u16,
    minor: u16,
    patch: u16,

    const latest: ChunkHeaderVersion = .{ .major = 0, .minor = 0, .patch = 1 };

    pub fn order(self: ChunkHeaderVersion, other: ChunkHeaderVersion) std.math.Order {
        const major = std.math.order(self.major, other.major);
        const minor = std.math.order(self.minor, other.minor);
        const patch = std.math.order(self.patch, other.patch);

        return switch (major) {
            .lt => .lt,
            .gt => .gt,
            .eq => switch (minor) {
                .lt => .lt,
                .gt => .gt,
                .eq => switch (patch) {
                    .lt => .lt,
                    .gt => .gt,
                    .eq => .eq,
                },
            },
        };
    }

    pub fn format(
        version: ChunkHeaderVersion,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        _ = options;
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, version);
        try writer.print("{[major]d}.{[minor]d}.{[patch]d}", version);
    }

    inline fn toBytes(chv: ChunkHeaderVersion) [6]u8 {
        const le = ChunkHeaderVersion{
            .major = std.mem.nativeToLittle(u16, chv.major),
            .minor = std.mem.nativeToLittle(u16, chv.minor),
            .patch = std.mem.nativeToLittle(u16, chv.patch),
        };
        return @bitCast(le);
    }
    inline fn fromBytes(bytes: [6]u8) ChunkHeaderVersion {
        const le: ChunkHeaderVersion = @bitCast(bytes);
        return ChunkHeaderVersion{
            .major = std.mem.littleToNative(u16, le.major),
            .minor = std.mem.littleToNative(u16, le.minor),
            .patch = std.mem.littleToNative(u16, le.patch),
        };
    }
};

pub const ChunkHeader = struct {
    version: ChunkHeaderVersion = ChunkHeaderVersion.latest,
    /// Should be the SHA of the blob comprised of the next chunk's header and data.
    /// If this is for the last chunk, it should simply be the SHA of the last chunk.
    next_chunk_blob_digest: [Sha256.digest_length]u8,
    /// Should be the SHA of the current chunk's data.
    current_chunk_digest: [Sha256.digest_length]u8,
    /// Should be non-`null` for the first chunk.
    full_file_digest: ?[Sha256.digest_length]u8,

    /// Calculate the name of this chunk (SHA256 digest of the header + the chunk data).
    pub fn calcName(
        header: *const ChunkHeader,
        /// Should be the reader passed to `readChunkHeader` to calculate the values of `header`, seeked
        /// back to the initial position before the `header` was calculated; that is to say, it should
        /// return the same data it returned during the aforementioned call to `readChunkHeader`.
        reader: anytype,
        /// `std.fifo.LinearFifo(u8, ...)`
        /// Used to pump the `reader` data through the SHA256 hash function
        fifo: anytype,
    ) @TypeOf(reader).Error![Sha256.digest_length]u8 {
        var hasher = Sha256.init(.{});
        const hasher_writer = util.sha256DigestCalcWriter(&hasher, std.io.null_writer).writer();
        writeChunkHeader(hasher_writer, header) catch |err| switch (err) {};

        var limited = std.io.limitedReader(reader, chunk_size);
        try fifo.pump(limited.reader(), hasher_writer);

        return hasher.finalResult();
    }

    pub inline fn byteCount(header: *const ChunkHeader) std.math.IntFittingRange(min_chunk_header, max_chunk_header) {
        var counter = std.io.countingWriter(std.io.null_writer);
        writeChunkHeader(counter.writer(), header) catch |err| switch (err) {};
        return @intCast(counter.bytes_written);
    }

    pub fn format(
        ch: ChunkHeader,
        comptime fmt_str: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) @TypeOf(writer).Error!void {
        if (fmt_str.len != 0) std.fmt.invalidFmtError(fmt_str, ch);
        _ = options;
        try writer.print("{}\r\n", .{ch.version});
        try writer.print("this: {s}\r\n", .{&digestBytesToString(&ch.current_chunk_digest)});
        try writer.print("next: {s}\r\n", .{&digestBytesToString(&ch.next_chunk_blob_digest)});
        if (ch.full_file_digest) |*full|
            try writer.print("full: {s}\r\n", .{&digestBytesToString(full)});
    }
};

const max_chunk_header: comptime_int = blk: {
    var counter = std.io.countingWriter(std.io.null_writer);
    writeChunkHeader(counter.writer(), &ChunkHeader{
        .next_chunk_blob_digest = .{0xFF} ** Sha256.digest_length,
        .current_chunk_digest = .{0xFF} ** Sha256.digest_length,
        .full_file_digest = .{0xFF} ** Sha256.digest_length,
    }) catch |err| @compileError(@errorName(err));
    break :blk counter.bytes_written;
};
const min_chunk_header: comptime_int = blk: {
    var counter = std.io.countingWriter(std.io.null_writer);
    writeChunkHeader(counter.writer(), &ChunkHeader{
        .version = .{ .major = 0, .minor = 0, .patch = 0 },
        .next_chunk_blob_digest = .{0} ** Sha256.digest_length,
        .current_chunk_digest = .{0} ** Sha256.digest_length,
        .full_file_digest = null,
    }) catch |err| @compileError(@errorName(err));
    break :blk counter.bytes_written;
};

pub fn writeChunkHeader(
    writer: anytype,
    header: *const ChunkHeader,
) @TypeOf(writer).Error!void {
    // write version
    try writer.writeAll(&header.version.toBytes());

    // write the SHA of the next chunk's header and data
    try writer.writeAll(&header.next_chunk_blob_digest);

    // write the SHA of the current' chunk's data
    try writer.writeAll(&header.current_chunk_digest);

    // write first chunk flag
    try writer.writeByte(@intFromBool(header.full_file_digest != null));

    // if this is the first chunk, write the full file SHA
    if (header.full_file_digest) |*digest| {
        try writer.writeAll(digest);
    }

    // TODO: write 'The sha(A + B) and sha(sha(A + B) + sha(C + D))'?
    // TODO: ask Ed what that means *exactly*
}

pub const ReadChunkHeaderError = error{
    UnrecognizedHeaderVersion,
    InvalidFirstChunkFlag,
};

pub fn readChunkHeader(reader: anytype) (@TypeOf(reader).Error || error{EndOfStream} || ReadChunkHeaderError)!ChunkHeader {
    // read version
    const version: ChunkHeaderVersion = blk: {
        const bytes = try reader.readBytesNoEof(6);
        break :blk ChunkHeaderVersion.fromBytes(bytes);
    };
    switch (version.order(ChunkHeaderVersion.latest)) {
        .gt => return error.UnrecognizedHeaderVersion,
        .lt => @panic("This should not yet be possible"),
        .eq => {},
    }

    // read the SHA of the next chunk's header and data
    const next_chunk_blob_digest = try reader.readBytesNoEof(Sha256.digest_length);

    // read the SHA of the current chunk's data
    const current_chunk_digest = try reader.readBytesNoEof(Sha256.digest_length);

    // read the first chunk flag
    const first_chunk_flag: bool = switch (try reader.readByte()) {
        0 => false,
        1 => true,
        else => return error.InvalidFirstChunkFlag,
    };

    // if this is the first chunk, read the full file SHA
    const full_file_digest: ?[Sha256.digest_length]u8 = if (first_chunk_flag) blk: {
        break :blk try reader.readBytesNoEof(Sha256.digest_length);
    } else null;

    // TODO: see the TODO in `writeChunkHeader` about 'The sha(A + B) and sha(sha(A + B) + sha(C + D))'

    return .{
        .version = version,
        .next_chunk_blob_digest = next_chunk_blob_digest,
        .current_chunk_digest = current_chunk_digest,
        .full_file_digest = full_file_digest,
    };
}

fn testChunkHeader(ch: ChunkHeader) !void {
    var bytes = std.BoundedArray(u8, max_chunk_header){};
    try writeChunkHeader(bytes.writer(), &ch);

    var fbs = std.io.fixedBufferStream(bytes.constSlice());
    const actual = try readChunkHeader(fbs.reader());
    try std.testing.expectEqual(ch, actual);
}

test ChunkHeader {
    try testChunkHeader(.{
        .next_chunk_blob_digest = try comptime digestStringToBytes("aB" ** Sha256.digest_length),
        .current_chunk_digest = try comptime digestStringToBytes("Cd" ** Sha256.digest_length),
        .full_file_digest = try comptime digestStringToBytes("eF" ** Sha256.digest_length),
    });
    try testChunkHeader(.{
        .next_chunk_blob_digest = try comptime digestStringToBytes("Ab" ** Sha256.digest_length),
        .current_chunk_digest = try comptime digestStringToBytes("cD" ** Sha256.digest_length),
        .full_file_digest = null,
    });
}

pub fn digestBytesToString(bytes: *const [Sha256.digest_length]u8) [Sha256.digest_length * 2]u8 {
    return std.fmt.bytesToHex(bytes.*, .lower);
}
pub fn digestStringToBytes(str: *const [Sha256.digest_length * 2]u8) error{ InvalidDigestLength, InvalidCharacter }![Sha256.digest_length]u8 {
    var digest = [_]u8{0} ** Sha256.digest_length;
    const digest_slice = std.fmt.hexToBytes(&digest, str) catch |err| switch (err) {
        error.InvalidLength => unreachable,
        error.NoSpaceLeft => unreachable,
        error.InvalidCharacter => |e| return e,
    };
    assert(digest.len == digest_slice.len);
    return digest;
}
