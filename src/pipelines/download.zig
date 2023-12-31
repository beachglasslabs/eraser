const chunk = @import("chunk.zig");
const eraser = @import("../pipelines.zig");
const erasure = eraser.erasure;
const Providers = @import("Providers.zig");
const ManagedQueue = @import("../managed_queue.zig").ManagedQueue;
const EncryptedFile = eraser.StoredFile;

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const util = @import("util");

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

        must_stop: std.atomic.Value(bool),
        queue_mtx: std.Thread.Mutex,
        queue_pop_re: std.Thread.ResetEvent,
        queue: ManagedQueue(QueueItem),

        providers: *const Providers,
        /// This mutex protects the `providers.auth` field.
        providers_auth_mtx: *std.Thread.Mutex,

        /// decrypted_chunk_buffer = &chunk_buffer[0]
        /// encrypted_chunk_buffer = &chunk_buffer[1]
        chunk_buffers: *[2][chunk.total_size]u8,

        random: std.rand.Random,
        ec: ErasureCoder,
        thread: ?std.Thread,
        const Self = @This();

        const ErasureCoder = erasure.Coder(W);
        const QueueItem = union(enum) {
            download: Download,

            const Download = struct {
                ctx: Ctx,
                stored_file: eraser.StoredFile,
                writer: DstWriter,
            };
        };

        // TODO: should this use a more strict memory order?
        const must_stop_store_mo: std.builtin.AtomicOrder = .Monotonic;
        const must_stop_load_mo: std.builtin.AtomicOrder = .Monotonic;

        pub const InitParams = struct {
            /// should be a thread-safe allocator
            allocator: std.mem.Allocator,
            /// should be thread-safe Pseudo-RNG
            random: std.rand.Random,
            /// initial capacity of the queue
            queue_capacity: usize,

            /// server providers
            providers: *const Providers,
            /// server providers mutex. locks access to `providers.auth`.
            providers_auth_mtx: *std.Thread.Mutex,
        };

        pub const InitError = std.mem.Allocator.Error || ErasureCoder.InitError;
        pub fn init(params: InitParams) InitError!Self {
            var queue = try ManagedQueue(QueueItem).initCapacity(params.allocator, params.queue_capacity);
            errdefer queue.deinit(params.allocator);

            const chunk_buffers = try params.allocator.create([2][chunk.total_size]u8);
            errdefer params.allocator.destroy(chunk_buffers);

            const ec = try ErasureCoder.init(params.allocator, .{
                .shard_count = @intCast(params.providers.shard_buckets.len),
                .shards_required = params.providers.shards_required,
            });
            errdefer ec.deinit(params.allocator);

            return .{
                .allocator = params.allocator,

                .must_stop = std.atomic.Value(bool).init(false),
                .queue_mtx = .{},
                .queue_pop_re = .{},
                .queue = queue,

                .providers = params.providers,
                .providers_auth_mtx = params.providers_auth_mtx,

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

            self.ec.deinit(self.allocator);
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
            return self.pushToQueue(.{ .download = .{
                .ctx = Ctx.init(ctx_ptr),
                .stored_file = params.stored_file.*,
                .writer = params.writer,
            } });
        }

        inline fn pushToQueue(
            self: *Self,
            item: QueueItem,
        ) std.mem.Allocator.Error!void {
            self.queue_mtx.lock();
            defer self.queue_mtx.unlock();
            self.queue_pop_re.set();
            return self.queue.pushValue(self.allocator, item);
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
            var http_client = std.http.Client{ .allocator = dpp.allocator };
            defer http_client.deinit();

            const decrypted_chunk_buffer: *[chunk.total_size]u8 = &dpp.chunk_buffers[0];
            const encrypted_chunk_buffer: *[chunk.total_size]u8 = &dpp.chunk_buffers[1];

            const Request = std.http.Client.Request;
            var requests = std.ArrayList(Request).init(dpp.allocator);
            defer requests.deinit();

            // backing buffer for all of the URIs for the shards of a chunk.
            const chunk_shards_uris_str_buf = dpp.allocator.alloc(u8, size: {
                var counter = std.io.countingWriter(std.io.null_writer);
                for (dpp.providers.shard_buckets) |shard_bucket| switch (shard_bucket) {
                    .gcloud => |bucket| bucket.writeUriTo(counter.writer(), .{
                        .protocol = "https",
                        .object = &eraser.digestBytesToString("\xAA" ** Sha256.digest_length),
                    }) catch |err| switch (err) {},

                    .aws => |bucket| bucket.writeUriTo(counter.writer(), .{
                        .protocol = "https",
                        .style = .path,
                        .object = &eraser.digestBytesToString("\xAA" ** Sha256.digest_length),
                    }) catch |err| switch (err) {},
                };
                break :size counter.bytes_written;
            }) catch |err| switch (err) {
                error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
            };
            defer dpp.allocator.free(chunk_shards_uris_str_buf);

            while (true) {
                const queue_item: QueueItem = blk: {
                    dpp.queue_pop_re.wait();

                    dpp.queue_mtx.lock();
                    defer dpp.queue_mtx.unlock();

                    break :blk dpp.queue.popValue() orelse {
                        dpp.queue_pop_re.reset();
                        if (dpp.must_stop.load(must_stop_load_mo)) break;
                        continue;
                    };
                };

                const down_data: QueueItem.Download = switch (queue_item) {
                    .download => |download| download,
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
                    const chunk_name = &current_chunk_info.chunk_blob_digest;

                    requests.clearRetainingCapacity();
                    defer for (requests.items) |*req| req.deinit();

                    {
                        // the headers are cloned for each request, so we re-use this as a buffer.
                        var headers = std.http.Headers.init(dpp.allocator);
                        defer headers.deinit();

                        var current_index: u8 = 0;

                        var uris_str_fbs = std.io.fixedBufferStream(chunk_shards_uris_str_buf);
                        for (dpp.providers.shard_buckets) |shard_bucket| {
                            {
                                if (current_index == dpp.providers.shard_buckets.len) break;
                                defer current_index += 1;
                                if (excluded_index_set.isSet(current_index)) continue;
                            }

                            const method: std.http.Method = switch (shard_bucket) {
                                .gcloud, .aws => .GET,
                            };
                            const uri = std.Uri.parse(str: {
                                const uri_start = uris_str_fbs.pos;
                                switch (shard_bucket) {
                                    // zig fmt: off
                                    .gcloud => |bucket| bucket.writeUriTo(uris_str_fbs.writer(), .{
                                        .protocol = "http",
                                        .object = &eraser.digestBytesToString(chunk_name),
                                    }) catch |err| switch (err) { error.NoSpaceLeft => unreachable },
                                    .aws => |bucket| bucket.writeUriTo(uris_str_fbs.writer(), .{
                                        .protocol = "http",
                                        .object = &eraser.digestBytesToString(chunk_name),
                                        .style = .path,
                                    }) catch |err| switch (err) { error.NoSpaceLeft => unreachable },
                                    // zig fmt: on
                                }
                                break :str chunk_shards_uris_str_buf[uri_start..uris_str_fbs.pos];
                            }) catch unreachable;

                            headers.clearRetainingCapacity();
                            switch (shard_bucket) {
                                .gcloud => {
                                    var auth_val_buf: [Providers.GoogleCloud.max_authorization_value_len]u8 = undefined;
                                    const auth_val: []const u8 = while (true) {
                                        // TODO: use better synchronization primitive to wait for this.
                                        // TODO: notify a callback of some sort that credentials are being awaited.
                                        dpp.providers_auth_mtx.lock();
                                        defer dpp.providers_auth_mtx.unlock();

                                        const gc = dpp.providers.auth.gcloud;
                                        break gc.getAuthorizationValue(&auth_val_buf) orelse continue;
                                    };

                                    headers.append("Authorization", auth_val) catch |err| @panic(@errorName(@as(std.mem.Allocator.Error, err)));
                                },
                                .aws => |bucket| {
                                    const Aws = Providers.Aws;
                                    const region_str = bucket.region.toBytes();
                                    const credentials: Aws.Credentials = while (true) {
                                        // TODO: use better synchronization primitive to wait for this.
                                        // TODO: notify a callback of some sort that credentials are being awaited.
                                        dpp.providers_auth_mtx.lock();
                                        defer dpp.providers_auth_mtx.unlock();

                                        const aws = dpp.providers.auth.aws;
                                        break aws.credentials orelse {
                                            std.Thread.yield() catch {};
                                            continue;
                                        };
                                    };
                                    const date_time = dt: {
                                        var date_time: std.BoundedArray(u8, "2000-12-31T00:00:00+00:00".len) = .{};
                                        const epoch_secs = std.time.epoch.EpochSeconds{
                                            .secs = std.math.cast(u64, std.time.timestamp()) orelse @panic("TODO: handle timestamp before epoch"),
                                        };
                                        Aws.iso8601.writeEpochYMDHMS(date_time.writer(), epoch_secs, .{
                                            .ymd = .dont_want_dashes,
                                            .hms = .dont_want_colons,
                                        }) catch unreachable;
                                        break :dt date_time;
                                    };
                                    Aws.http.sortAndAddAuthHeaders(dpp.allocator, &headers, .{
                                        .request_method = @tagName(method),
                                        .request_uri = uri,
                                        .request_uri_already_encoded = true,

                                        .date_time = date_time.constSlice(),
                                        .service = "s3",
                                        .region = region_str.constSlice(),

                                        .access_key_id = &credentials.access_key_id.string,
                                        .secret_access_key = &credentials.secret_access_key.string,
                                        .session_token = credentials.session_token.string,

                                        .payload_sign = .{ .special = .unsigned_payload },
                                    }) catch |err| @panic(switch (err) {
                                        inline else => |e| "Decide how to handle " ++ @errorName(e),
                                    });
                                },
                            }

                            var req = http_client.open(method, uri, headers, .{}) catch |err| switch (err) {
                                error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                                inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                            };
                            errdefer req.deinit();

                            // zig fmt: off
                            req.send(.{}) catch |err| switch (err) { inline else => |e| @panic("TODO: handle " ++ @errorName(e)) };
                            req.finish() catch |err| switch (err) { inline else => |e| @panic("TODO: handle " ++ @errorName(e)) };
                            req.wait() catch |err| switch (err) { inline else => |e| @panic("TODO: handle " ++ @errorName(e)) };
                            // zig fmt: on

                            switch (req.response.status) {
                                .ok => {},
                                else => |status| {
                                    std.debug.print("\nStatus: {}\nHeaders:\n---\n{}\n---\n", .{ status, req.response.headers });
                                    {
                                        std.debug.getStderrMutex().lock();
                                        defer std.debug.getStderrMutex().unlock();
                                        util.pumpReaderToWriterThroughFifo(req.reader(), std.io.getStdErr().writer(), .static, 4096) catch {};
                                    }
                                    @panic("TODO: Handle other response statuses");
                                },
                            }

                            requests.append(req) catch |err| switch (err) {
                                error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                            };
                        }
                    }

                    const ReadersCtx = struct {
                        requests: []Request,
                        down_ctx: Ctx,

                        const ReaderCtx = struct {
                            request: *Request,
                            down_ctx: Ctx,

                            const ReadError = Request.ReadError;
                            fn read(self: @This(), buf: []u8) !usize {
                                const bytes_read = self.request.read(buf);
                                return bytes_read;
                            }
                        };
                        pub inline fn getReader(ctx: @This(), reader_idx: u7) std.io.Reader(ReaderCtx, ReaderCtx.ReadError, ReaderCtx.read) {
                            return .{
                                .context = .{
                                    .request = &ctx.requests[reader_idx],
                                    .down_ctx = ctx.down_ctx,
                                },
                            };
                        }
                    };

                    const readers_ctx = ReadersCtx{
                        .requests = requests.items,
                        .down_ctx = down_ctx,
                    };

                    var ecd_fbs = std.io.fixedBufferStream(encrypted_chunk_buffer);
                    _ = dpp.ec.decodeCtx(excluded_index_set, ecd_fbs.writer(), readers_ctx) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        inline error.EndOfStream => |e| @panic("Decide how to handle " ++ @errorName(e)),
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
