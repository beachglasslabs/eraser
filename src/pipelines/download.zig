const chunk = @import("chunk.zig");
const eraser = @import("../pipelines.zig");
const erasure = eraser.erasure;
const ServerInfo = @import("ServerInfo.zig");
const ManagedQueue = @import("../managed_queue.zig").ManagedQueue;
const EncryptedFile = eraser.StoredFile;

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const util = @import("../util.zig");

pub inline fn pipeLine(
    comptime W: type,
    comptime DstWriter: type,
    init_values: PipeLine(W, DstWriter).InitParams,
) PipeLine(W, DstWriter).InitError!PipeLine(W, DstWriter) {
    return PipeLine(W, DstWriter).init(init_values);
}

pub fn PipeLine(
    comptime W: type,
    /// `std.io.Writer(...)`
    comptime DstWriter: type,
) type {
    return struct {
        //! All fields in this container are private and not to be modified directly unless
        //! explicitly stated otherwise in the field's doc comment.

        allocator: std.mem.Allocator,
        requests_buf: []std.http.Client.Request,
        server_info: ServerInfo,
        gc_prealloc: ?ServerInfo.GoogleCloud.PreAllocated,

        must_stop: std.atomic.Atomic(bool),
        queue_mtx: std.Thread.Mutex,
        queue_pop_re: std.Thread.ResetEvent,
        queue: ManagedQueue(QueueItem),

        /// decrypted_chunk_buffer = &chunk_buffer[0]
        /// encrypted_chunk_buffer = &chunk_buffer[1]
        chunk_buffers: *[2][header_plus_chunk_max_size]u8,

        random: std.rand.Random,
        ec: ErasureCoder,
        thread: ?std.Thread,
        const Self = @This();

        const header_plus_chunk_max_size = chunk.Header.size + chunk.size;

        const ErasureCoder = erasure.Coder(W);

        // TODO: should this use a more strict memory order?
        const must_stop_store_mo: std.builtin.AtomicOrder = .Monotonic;
        const must_stop_load_mo: std.builtin.AtomicOrder = .Monotonic;

        const QueueItem = struct {
            ctx: Ctx,
            stored_file: eraser.StoredFile,
            writer: DstWriter,
        };

        pub const InitParams = struct {
            /// should be a thread-safe allocator
            allocator: std.mem.Allocator,
            /// should be thread-safe Pseudo-RNG
            random: std.rand.Random,
            /// initial capacity of the queue
            queue_capacity: usize,
            /// server provider configuration
            server_info: ServerInfo,
        };

        pub const InitError = std.mem.Allocator.Error || ErasureCoder.InitError;
        pub fn init(params: InitParams) InitError!Self {
            const gc_prealloc = if (params.server_info.google_cloud) |gc| try gc.preAllocated(params.allocator) else null;
            errdefer if (gc_prealloc) |pre_alloc| pre_alloc.deinit(params.allocator);

            var queue = try ManagedQueue(QueueItem).initCapacity(params.allocator, params.queue_capacity);
            errdefer queue.deinit(params.allocator);

            const requests_buf = try params.allocator.alloc(std.http.Client.Request, params.server_info.bucketCount());
            errdefer params.allocator.free(requests_buf);

            const chunk_buffers = try params.allocator.create([2][header_plus_chunk_max_size]u8);
            errdefer params.allocator.destroy(chunk_buffers);

            const ec = try ErasureCoder.init(params.allocator, .{
                .shard_count = @intCast(params.server_info.bucketCount()),
                .shards_required = params.server_info.shards_required,
            });
            errdefer ec.deinit(params.allocator);

            return .{
                .allocator = params.allocator,
                .server_info = params.server_info,
                .gc_prealloc = gc_prealloc,

                .must_stop = std.atomic.Atomic(bool).init(false),
                .queue_mtx = .{},
                .queue_pop_re = .{},
                .queue = queue,

                .requests_buf = requests_buf,
                .chunk_buffers = chunk_buffers,

                .random = params.random,
                .ec = ec,
                .thread = null,
            };
        }

        pub fn deinit(
            self: *Self,
            remaining_queue_fate: enum {
                finish_remaining_downloads,
                cancel_remaining_downloads,
            },
        ) void {
            self.must_stop.store(true, must_stop_store_mo);
            switch (remaining_queue_fate) {
                .finish_remaining_downloads => {},
                .cancel_remaining_downloads => {
                    self.queue_mtx.lock();
                    defer self.queue_mtx.unlock();
                    self.queue.clearItems();
                },
            }

            self.queue_pop_re.set();
            if (self.thread) |thread| thread.join();
            self.queue.deinit(self.allocator);

            self.allocator.destroy(self.chunk_buffers);
            self.allocator.free(self.requests_buf);

            self.ec.deinit(self.allocator);
            if (self.gc_prealloc) |pre_alloc| pre_alloc.deinit(self.allocator);
        }

        pub inline fn start(self: *Self) std.Thread.SpawnError!void {
            assert(self.thread == null);
            self.thread = try std.Thread.spawn(.{ .allocator = self.allocator }, downloadPipeLineThread, .{self});
        }

        const DownloadParams = struct {
            /// The output to which the file contents will be written.
            writer: DstWriter,
            /// The handle representing the stored file on the server.
            stored_file: *const eraser.StoredFile,
        };
        pub fn downloadFile(
            self: *Self,
            ctx_ptr: anytype,
            params: DownloadParams,
        ) !void {
            self.queue_mtx.lock();
            defer self.queue_mtx.unlock();
            self.queue_pop_re.set();
            try self.queue.pushValue(self.allocator, QueueItem{
                .ctx = Ctx.init(ctx_ptr),
                .writer = params.writer,
                .stored_file = params.stored_file.*,
            });
        }

        const Ctx = struct {
            ptr: *anyopaque,
            actionFn: *const fn (ptr: *anyopaque, state: Action) void,

            fn init(ctx_ptr: anytype) Ctx {
                const Ptr = @TypeOf(ctx_ptr);
                const gen = struct {
                    fn actionFn(erased_ptr: *anyopaque, action_data: Ctx.Action) void {
                        const ptr: Ptr = @ptrCast(@alignCast(erased_ptr));
                        switch (action_data) {
                            .update => |percentage| ptr.update(percentage),
                            .close => |dst| ptr.close(dst),
                        }
                    }
                };
                return .{
                    .ptr = @ptrCast(ctx_ptr),
                    .actionFn = gen.actionFn,
                };
            }

            pub inline fn update(self: Ctx, percentage: u8) void {
                return self.action(.{ .update = percentage });
            }

            pub inline fn close(self: Ctx, dst: DstWriter) void {
                return self.action(.{ .close = dst });
            }

            inline fn action(self: Ctx, data: Action) void {
                return self.actionFn(self.ptr, data);
            }

            pub const Action = union(enum) {
                /// percentage of progress
                update: u8,
                close: DstWriter,
            };
        };

        fn downloadPipeLineThread(dpp: *Self) void {
            var client = std.http.Client{ .allocator = dpp.allocator };
            defer client.deinit();

            const decrypted_chunk_buffer: *[header_plus_chunk_max_size]u8 = &dpp.chunk_buffers[0];
            const encrypted_chunk_buffer: *[header_plus_chunk_max_size]u8 = &dpp.chunk_buffers[1];

            while (true) {
                const down_data: QueueItem = blk: {
                    dpp.queue_pop_re.wait();

                    dpp.queue_mtx.lock();
                    defer dpp.queue_mtx.unlock();

                    break :blk dpp.queue.popValue() orelse {
                        dpp.queue_pop_re.reset();
                        if (dpp.must_stop.load(must_stop_load_mo)) break;
                        continue;
                    };
                };
                const down_ctx = down_data.ctx;
                defer down_ctx.close(down_data.writer);

                const excluded_index_set = erasure.sampleIndexSet(
                    dpp.random,
                    dpp.ec.shardCount(),
                    dpp.ec.shardCount() - dpp.ec.shardsRequired(),
                );

                var full_file_digest = [_]u8{0} ** Sha256.digest_length;
                var current_chunk_info: chunk.ChunkRef = .{
                    .chunk_blob_digest = down_data.stored_file.first_name,
                    .encryption = down_data.stored_file.encryption,
                };

                var chunks_encountered: chunk.Count = 0;
                while (true) {
                    if (chunks_encountered == down_data.stored_file.chunk_count) {
                        if (!std.mem.allEqual(u8, &current_chunk_info.chunk_blob_digest, 0)) {
                            @panic("TODO handle: more chunks encountered than specified");
                        } else break;
                    }
                    chunks_encountered += 1;

                    var requests = util.BoundedBufferArray(std.http.Client.Request){ .buffer = dpp.requests_buf };
                    defer for (requests.slice()) |*req| req.deinit();

                    { // populate `requests`
                        var current_index: u8 = 0;

                        if (dpp.server_info.google_cloud) |gc| {
                            const gc_prealloc = dpp.gc_prealloc.?;

                            var iter = gc_prealloc.bucketObjectUriIterator(gc, &current_chunk_info.chunk_blob_digest);
                            while (iter.next()) |uri_str| : (current_index += 1) {
                                if (excluded_index_set.isSet(current_index)) continue;

                                const uri = std.Uri.parse(uri_str) catch unreachable;
                                const req = client.request(.GET, uri, gc_prealloc.headers.toManaged(dpp.allocator), .{}) catch |err| switch (err) {
                                    error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                                    inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                                };
                                requests.appendAssumingCapacity(req);
                            }
                        }
                    }

                    for (requests.slice()) |*req| {
                        req.start() catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        req.finish() catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        req.wait() catch |err| switch (err) {
                            error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                    }

                    const ReadersCtx = struct {
                        requests: []std.http.Client.Request,
                        down_ctx: Ctx,

                        const ReaderCtx = struct {
                            inner: Inner,
                            down_ctx: Ctx,

                            const Inner = std.http.Client.Request.Reader;
                            fn read(self: @This(), buf: []u8) Inner.Error!usize {
                                const result = try self.inner.read(buf);
                                return result;
                            }
                        };
                        pub inline fn getReader(ctx: @This(), reader_idx: u7) std.io.Reader(ReaderCtx, ReaderCtx.Inner.Error, ReaderCtx.read) {
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

                    var ecd_fbs = std.io.fixedBufferStream(encrypted_chunk_buffer);
                    _ = dpp.ec.decodeCtx(excluded_index_set, ecd_fbs.writer(), readers_ctx) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        inline error.NoSpaceLeft => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                    const encrypted_blob_data: []const u8 = ecd_fbs.getWritten();

                    const auth_tag = current_chunk_info.encryption.tag;
                    const npub = current_chunk_info.encryption.npub;
                    const key = current_chunk_info.encryption.key;
                    Aes256Gcm.decrypt(
                        decrypted_chunk_buffer[0..encrypted_blob_data.len],
                        encrypted_blob_data,
                        auth_tag,
                        "",
                        npub,
                        key,
                    ) catch |err| switch (err) {
                        inline error.AuthenticationFailed => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                    const decrypted_blob_data: []const u8 = decrypted_chunk_buffer[0..encrypted_blob_data.len];

                    const header = chunk.Header.fromBytes(decrypted_blob_data[0..chunk.Header.size]) catch |err| switch (err) {
                        inline error.UnrecognizedHeaderVersion => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                    const decrypted_chunk_data = decrypted_blob_data[chunk.Header.size..];

                    current_chunk_info = header.next;
                    full_file_digest = header.full_file_digest;

                    down_data.writer.writeAll(decrypted_chunk_data) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                }
            }
        }
    };
}
