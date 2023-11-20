const chunk = @import("chunk.zig");
const eraser = @import("../pipelines.zig");
const erasure = eraser.erasure;
const iso8601 = @import("../iso-8601.zig");
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

        must_stop: std.atomic.Atomic(bool),
        queue_mtx: std.Thread.Mutex,
        queue_pop_re: std.Thread.ResetEvent,
        queue: ManagedQueue(QueueItem),

        providers: *const Providers,
        /// This mutex protects the `providers` field.
        providers_mtx: *std.Thread.Mutex,

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

            /// server providers
            providers: *const Providers,
            /// server providers mutex. locks access to the given `providers` pointer.
            providers_mtx: *std.Thread.Mutex,
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
                .providers_mtx = params.providers_mtx,

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
            var http_client = std.http.Client{ .allocator = dpp.allocator };
            defer http_client.deinit();

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
                                var req = http_client.open(.GET, uri, gc_headers, .{}) catch |err| switch (err) {
                                    error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                                    inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                                };
                                defer req.deinit();

                                // zig fmt: off
                                req.send(.{}) catch |err| switch (err) { inline else => |e| @panic("TODO: handle " ++ @errorName(e)) };
                                req.finish() catch |err| switch (err) { inline else => |e| @panic("TODO: handle " ++ @errorName(e)) };
                                req.wait() catch |err| switch (err) { inline else => |e| @panic("TODO: handle " ++ @errorName(e)) };
                                // zig fmt: on

                                switch (req.response.status) {
                                    .ok => {},
                                    else => @panic("TODO: Handle other response statuses"),
                                }

                                util.pumpReaderToWriterThroughFifo(req.reader(), shard_datas.buffer.writer(dpp.allocator), .static, 4096) catch |err| switch (err) {
                                    inline else => |e| @panic("TODO: handle " ++ @errorName(e)),
                                };
                                shard_datas.finishCurrent(dpp.allocator) catch |err| switch (err) {
                                    inline else => |e| @panic("TODO: handle " ++ @errorName(e)),
                                };
                            }
                        };

                        if (current_index != dpp.providers.bucketCount()) if (dpp.providers.aws) |aws| aws_blk: {
                            const credentials = aws.credentials orelse break :aws_blk;

                            var headers = std.http.Headers.init(dpp.allocator);
                            defer headers.deinit();

                            const method: std.http.Method = .GET;

                            const date_time = dt: {
                                var date_time: std.BoundedArray(u8, "2000-12-31T00:00:00Z".len) = .{};

                                const epoch_secs = std.time.epoch.EpochSeconds{
                                    .secs = std.math.cast(u64, std.time.timestamp()) orelse @panic("TODO: handle timestamp before epoch"),
                                };
                                const year, const month, const day = ymd: {
                                    const epoch_day = epoch_secs.getEpochDay();
                                    const year_day = epoch_day.calculateYearDay();
                                    const month_day = year_day.calculateMonthDay();
                                    break :ymd .{ year_day.year, month_day.month, month_day.day_index + 1 };
                                };
                                const hour, const minute, const second = hms: {
                                    const ds = epoch_secs.getDaySeconds();
                                    break :hms .{ ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute() };
                                };

                                iso8601.writeYearMonthDayTo(date_time.writer(), year, month, day, .{ .want_dashes = false }) catch unreachable;
                                date_time.writer().print("T{d:0>2}{d:0>2}{d:0>2}Z", .{ hour, minute, second }) catch unreachable;
                                break :dt date_time;
                            };

                            var uri_str_buf = std.ArrayList(u8).init(dpp.allocator);
                            defer uri_str_buf.deinit();

                            for (aws.buckets) |bucket| {
                                {
                                    if (current_index == dpp.providers.bucketCount()) break;
                                    defer current_index += 1;
                                    if (excluded_index_set.isSet(current_index)) continue;
                                }

                                const region_str = bucket.region.toBytes();
                                const uri = std.Uri.parse(str: {
                                    uri_str_buf.clearRetainingCapacity();
                                    uri_str_buf.writer().print("{[bucket]}/{[object]s}", .{
                                        .bucket = bucket.fmtUri(.{ .protocol = "http", .style = .path }),
                                        .object = eraser.digestBytesToString(chunk_name),
                                    }) catch |err| switch (err) {
                                        error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                                    };
                                    break :str uri_str_buf.items;
                                }) catch |err| switch (err) {
                                    inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                                };

                                headers.clearRetainingCapacity();
                                Providers.Aws.http.sortAndAddHeaders(dpp.allocator, &headers, .{
                                    .request_method = @tagName(method),
                                    .request_uri = uri,

                                    .date_time = date_time.constSlice(),
                                    .service = "s3",
                                    .region = region_str.constSlice(),

                                    .access_key_id = credentials.access_key_id.getSensitiveSlice(),
                                    .secret_access_key = credentials.secret_access_key.getSensitiveSlice(),
                                    .session_token = credentials.session_token.getSensitiveSlice(),

                                    .payload_sign = .{ .special = .unsigned_payload },
                                }) catch |err| @panic(switch (err) {
                                    inline else => |e| "Decide how to handle " ++ @errorName(e),
                                });

                                var req = http_client.open(method, uri, headers, .{}) catch |err| switch (err) {
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
