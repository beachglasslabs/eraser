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
const zaws = @import("zaws");

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

        must_stop: std.atomic.Atomic(bool),
        queue_mtx: std.Thread.Mutex,
        queue_pop_re: std.Thread.ResetEvent,
        queue: ManagedQueue(QueueItem),

        providers: Providers,
        providers_mtx: std.Thread.Mutex,

        request_uris_buf: []u8,
        requests_buf: []std.http.Client.Request,
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
            /// server provider configuration
            providers: Providers,
        };

        pub const InitError = std.mem.Allocator.Error || ErasureCoder.InitError;
        pub fn init(params: InitParams) InitError!Self {
            var queue = try ManagedQueue(QueueItem).initCapacity(params.allocator, params.queue_capacity);
            errdefer queue.deinit(params.allocator);

            const request_uris_buf: []u8 = if (params.providers.google_cloud) |gc|
                try params.allocator.alloc(u8, gc.objectUriIteratorBufferSize())
            else
                &.{};
            errdefer params.allocator.free(request_uris_buf);

            const requests_buf = try params.allocator.alloc(std.http.Client.Request, params.providers.bucketCount());
            errdefer params.allocator.free(requests_buf);

            const chunk_buffers = try params.allocator.create([2][chunk.total_size]u8);
            errdefer params.allocator.destroy(chunk_buffers);

            const ec = try ErasureCoder.init(params.allocator, .{
                .shard_count = @intCast(params.providers.bucketCount()),
                .shards_required = params.providers.shards_required,
            });
            errdefer ec.deinit(params.allocator);

            return .{
                .allocator = params.allocator,

                .must_stop = std.atomic.Atomic(bool).init(false),
                .queue_mtx = .{},
                .queue_pop_re = .{},
                .queue = queue,

                .providers = params.providers,
                .providers_mtx = .{},

                .request_uris_buf = request_uris_buf,
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
            self.allocator.free(self.request_uris_buf);

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

        pub fn updateGoogleCloudAuthTok(
            self: *Self,
            auth_tok: eraser.SensitiveBytes.Bounded(Providers.GoogleCloud.max_auth_token_len),
        ) void {
            self.providers_mtx.lock();
            defer self.providers_mtx.unlock();

            if (self.providers.google_cloud) |*gc| {
                gc.auth_token = auth_tok;
            }
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
            var client = std.http.Client{ .allocator = dpp.allocator };
            defer client.deinit();

            const decrypted_chunk_buffer: *[chunk.total_size]u8 = &dpp.chunk_buffers[0];
            const encrypted_chunk_buffer: *[chunk.total_size]u8 = &dpp.chunk_buffers[1];

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

                    var shard_datas = ContiguousStringAppender{};
                    defer shard_datas.deinit(dpp.allocator);

                    var gc_headers = std.http.Headers.init(dpp.allocator);
                    defer gc_headers.deinit();
                    gc_headers.owned = true;

                    {
                        var current_index: u8 = 0;

                        if (current_index != dpp.providers.bucketCount()) if (dpp.providers.google_cloud) |gc| gc_blk: {
                            const authval = gc.authorizationValue() orelse break :gc_blk;
                            gc_headers.append("Authorization", authval.constSlice()) catch |err| @panic(@errorName(@as(std.mem.Allocator.Error, err)));

                            var iter = gc.objectUriIterator(&current_chunk_info.chunk_blob_digest, dpp.request_uris_buf);
                            while (iter.next()) |uri_str| {
                                {
                                    if (current_index == dpp.providers.bucketCount()) break;
                                    defer current_index += 1;
                                    if (excluded_index_set.isSet(current_index)) continue;
                                }

                                const uri = std.Uri.parse(uri_str) catch unreachable;
                                var req = client.open(.GET, uri, gc_headers, .{}) catch |err| switch (err) {
                                    error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                                    inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                                };
                                defer req.deinit();

                                // zig fmt: off
                                req.send(.{}) catch |err| switch (err) { inline else => |e| @panic("TODO: handle " ++ @errorName(e)) };
                                req.finish() catch |err| switch (err) { inline else => |e| @panic("TODO: handle " ++ @errorName(e)) };
                                req.wait() catch |err| switch (err) { inline else => |e| @panic("TODO: handle " ++ @errorName(e)) };
                                // zig fmt: on

                                var fifo = std.fifo.LinearFifo(u8, .{ .Static = 4096 }).init();

                                fifo.pump(req.reader(), shard_datas.buffer.writer(dpp.allocator)) catch |err| switch (err) {
                                    inline else => |e| @panic("TODO: handle " ++ @errorName(e)),
                                };
                                shard_datas.finishCurrent(dpp.allocator) catch |err| switch (err) {
                                    inline else => |e| @panic("TODO: handle " ++ @errorName(e)),
                                };
                            }
                        };

                        if (current_index != dpp.providers.bucketCount()) if (dpp.providers.aws) |aws| {
                            const ctx = aws.ctx;

                            for (aws.buckets) |bucket| {
                                {
                                    if (current_index == dpp.providers.bucketCount()) break;
                                    defer current_index += 1;
                                    if (excluded_index_set.isSet(current_index)) continue;
                                }

                                const region_str_bytes = bucket.region.toBytes();

                                const request_path = "/".* ++ eraser.digestBytesToString(chunk_name);

                                const host_name_str = std.fmt.allocPrint(dpp.allocator, "{s}.s3.amazonaws.com", .{bucket.name}) catch |e| @panic(@errorName(e));
                                defer dpp.allocator.free(host_name_str);

                                const req_message = zaws.HttpMessage.newRequest(&ctx.aws_ally) orelse @panic("Failed to initialise HTTP message");
                                defer req_message.release();

                                req_message.setRequestMethod("GET") catch |e| @panic(@errorName(e));
                                req_message.setRequestPath(&request_path) catch |e| @panic(@errorName(e));

                                const ReqCtx = struct {
                                    re: std.Thread.ResetEvent = .{},
                                    maybe_err: BodyError!void = {},
                                    allocator: std.mem.Allocator,
                                    shard_datas: *ContiguousStringAppender,

                                    const BodyError = std.mem.Allocator.Error || error{};

                                    fn bodyCallback(
                                        meta_request: ?*zaws.c.aws_s3_meta_request,
                                        body: [*c]const zaws.c.aws_byte_cursor,
                                        range_start: u64,
                                        user_data: ?*anyopaque,
                                    ) callconv(.C) c_int {
                                        _ = range_start;
                                        _ = meta_request;
                                        const req_ctx: *@This() = @alignCast(@ptrCast(user_data.?));
                                        defer req_ctx.re.set();

                                        req_ctx.shard_datas.buffer.appendSlice(req_ctx.allocator, zaws.byteCursorToSlice(body[0]).?) catch |err| {
                                            req_ctx.maybe_err = err;
                                            return zaws.c.AWS_OP_SUCCESS;
                                        };

                                        return zaws.c.AWS_OP_SUCCESS;
                                    }

                                    fn finishCallback(
                                        meta_request: ?*zaws.c.aws_s3_meta_request,
                                        meta_request_result: [*c]const zaws.c.aws_s3_meta_request_result,
                                        user_data: ?*anyopaque,
                                    ) callconv(.C) void {
                                        _ = meta_request;
                                        _ = meta_request_result;
                                        const req_ctx: *@This() = @alignCast(@ptrCast(user_data.?));
                                        defer req_ctx.re.set();
                                    }
                                };
                                var req_ctx: ReqCtx = .{
                                    .allocator = dpp.allocator,
                                    .shard_datas = &shard_datas,
                                };

                                // TODO: get this working with https
                                var endpoint_uri = zaws.Uri.initFromBuilderOptions(&ctx.aws_ally, .{
                                    // .scheme = zaws.byteCursorFromSlice(@constCast("https")),
                                    .scheme = zaws.byteCursorFromSlice(@constCast("http")),

                                    .host_name = zaws.byteCursorFromSlice(host_name_str),
                                    .path = zaws.byteCursorFromSlice(@constCast(&request_path)),

                                    // .port = 443,
                                    .port = 80,

                                    .query_params = null,
                                    .query_string = .{},
                                }) catch |err| switch (err) {
                                    inline else => |e| @panic("TODO: Handle " ++ @errorName(e)),
                                };
                                defer endpoint_uri.cleanUp();

                                const signing_config = zaws.signing_config.wrapperToBytes(.{
                                    .config_type = zaws.c.AWS_SIGNING_CONFIG_AWS,
                                    .algorithm = zaws.c.AWS_SIGNING_ALGORITHM_V4,
                                    .signature_type = zaws.c.AWS_ST_HTTP_REQUEST_HEADERS,

                                    .date = zaws.DateTime.initNow().value,
                                    .region = zaws.byteCursorFromSlice(@constCast(region_str_bytes.constSlice())), // this should just get read, the C API just doesn't express this constness
                                    .service = zaws.byteCursorFromSlice(@constCast("s3")), // this should just get read, the C API just doesn't express this constness

                                    .should_sign_header = null,
                                    .should_sign_header_ud = null,

                                    .flags = .{
                                        .use_double_uri_encode = false,
                                    },

                                    .signed_body_header = zaws.c.AWS_SBHT_X_AMZ_CONTENT_SHA256,
                                    .signed_body_value = zaws.byteCursorFromSlice(null), // leave empty to make AWS calculate it

                                    .credentials = null,
                                    .credentials_provider = ctx.credentials_provider.ptr,

                                    .expiration_in_seconds = 0,
                                });

                                const req = ctx.client.makeMetaRequest(.{
                                    .type = zaws.c.AWS_S3_META_REQUEST_TYPE_GET_OBJECT,
                                    .signing_config = &signing_config,
                                    .message = req_message.ptr,

                                    .send_filepath = zaws.byteCursorFromSlice(null),
                                    .send_async_stream = null,
                                    .checksum_config = null,

                                    .user_data = &req_ctx,
                                    .headers_callback = null,
                                    .body_callback = ReqCtx.bodyCallback,
                                    .finish_callback = ReqCtx.finishCallback,
                                    .shutdown_callback = null,
                                    .progress_callback = null,
                                    .telemetry_callback = null,
                                    .upload_review_callback = null,

                                    .endpoint = &endpoint_uri.value,
                                    .resume_token = null,
                                }) orelse @panic("Failed to create meta request");
                                defer req.release();

                                req_ctx.re.wait();
                                req_ctx.maybe_err catch |err| switch (err) {
                                    inline else => |e| @panic("TODO: handle " ++ @errorName(e)),
                                };
                                shard_datas.finishCurrent(dpp.allocator) catch |err| switch (err) {
                                    inline else => |e| @panic("TODO: handle " ++ @errorName(e)),
                                };
                            }
                        };
                    }

                    const shard_data_cursors = dpp.allocator.alloc(usize, shard_datas.count()) catch |e| @panic(@errorName(e));
                    defer dpp.allocator.free(shard_data_cursors);
                    @memset(shard_data_cursors, 0);

                    const ReadersCtx = struct {
                        shard_datas: *const ContiguousStringAppender,
                        cursors: []usize,
                        down_ctx: Ctx,

                        const ReaderCtx = struct {
                            shard_data: []const u8,
                            cursor: *usize,
                            down_ctx: Ctx,

                            const ReadError = error{};
                            fn read(self: @This(), buf: []u8) !usize {
                                var fbs = std.io.fixedBufferStream(self.shard_data[self.cursor.*..]);
                                const read_count = try fbs.reader().read(buf);
                                self.cursor.* += read_count;
                                return read_count;
                            }
                        };
                        pub inline fn getReader(ctx: @This(), reader_idx: u7) std.io.Reader(ReaderCtx, ReaderCtx.ReadError, ReaderCtx.read) {
                            return .{ .context = .{
                                .shard_data = ctx.shard_datas.getString(reader_idx),
                                .cursor = &ctx.cursors[reader_idx],
                                .down_ctx = ctx.down_ctx,
                            } };
                        }
                    };

                    const readers_ctx = ReadersCtx{
                        .shard_datas = &shard_datas,
                        .cursors = shard_data_cursors,
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

const ContiguousStringAppender = struct {
    ends: std.ArrayListUnmanaged(u64) = .{},
    buffer: std.ArrayListUnmanaged(u8) = .{},

    fn deinit(csa: *ContiguousStringAppender, allocator: std.mem.Allocator) void {
        csa.ends.deinit(allocator);
        csa.buffer.deinit(allocator);
    }

    inline fn count(csa: ContiguousStringAppender) usize {
        return csa.ends.items.len;
    }

    inline fn finishCurrent(csa: *ContiguousStringAppender, allocator: std.mem.Allocator) !void {
        try csa.ends.append(allocator, csa.buffer.items.len);
    }

    inline fn getString(csa: ContiguousStringAppender, index: usize) []const u8 {
        assert(csa.ends.items.len != 0);

        const ends = csa.ends.items;
        const buffer: []const u8 = csa.buffer.items;

        // zig fmt: off
        const start_idx = if (index != 0       ) ends[index - 1] else 0;
        const end_idx   = if (index != ends.len) ends[index    ] else buffer.len;
        // zig fmt: on

        return buffer[start_idx..end_idx];
    }

    inline fn iterator(csa: *const ContiguousStringAppender) Iterator {
        return .{
            .csa = csa,
            .index = 0,
        };
    }

    const Iterator = struct {
        csa: *const ContiguousStringAppender,
        index: usize,

        inline fn next(iter: *Iterator) ?[]const u8 {
            if (iter.csa.count() == iter.index) return null;
            defer iter.index += 1;
            return iter.csa.getString(iter.index);
        }
    };
};

test ContiguousStringAppender {
    var csa = ContiguousStringAppender{};
    defer csa.deinit(std.testing.allocator);

    try csa.buffer.writer(std.testing.allocator).print("1 + 2 = {d}", .{1 + 2});
    try csa.finishCurrent(std.testing.allocator);

    try csa.buffer.appendSlice(std.testing.allocator, "foo bar baz");
    try csa.finishCurrent(std.testing.allocator);

    try csa.buffer.appendSlice(std.testing.allocator, "fizz buzz");
    try csa.finishCurrent(std.testing.allocator);

    var i: usize = 0;
    var iter = csa.iterator();
    while (iter.next()) |str| : (i += 1) {
        try std.testing.expectEqualStrings(([_][]const u8{
            "1 + 2 = 3",
            "foo bar baz",
            "fizz buzz",
        })[i], str);
    }
}
