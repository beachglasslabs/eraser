const chunk = @import("chunk.zig");
const eraser = @import("../pipelines.zig");
const erasure = eraser.erasure;
const iso8601 = @import("../iso-8601.zig");
const Providers = @import("Providers.zig");
const ManagedQueue = @import("../managed_queue.zig").ManagedQueue;
const StoredFile = eraser.StoredFile;

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const util = @import("util");

pub inline fn pipeLine(
    comptime W: type,
    comptime Src: type,
    init_values: PipeLine(W, Src).InitParams,
) PipeLine(W, Src).InitError!PipeLine(W, Src) {
    return PipeLine(W, Src).init(init_values);
}

pub fn PipeLine(
    comptime W: type,
    /// `Src.Reader`         = `std.io.Reader(...)`
    /// `Src.SeekableStream` = `std.io.SeekableStream(...)`
    /// `Src.reader`         = `fn (Src) Src.Reader`
    /// `Src.seekableStream` = `fn (Src) Src.SeekableStream`
    comptime Src: type,
) type {
    const SrcNs = verifySrcType(Src) catch |err| @compileError(@errorName(err));
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

        full_request_uri_buf: []u8,
        request_uri_bufs: RequestUriBuffers,

        /// decrypted_chunk_buffer = &chunk_buffer[0]
        /// encrypted_chunk_buffer = &chunk_buffer[1]
        chunk_buffers: *[2][chunk.total_size]u8,

        random: std.rand.Random,
        ec: ErasureCoder,
        thread: ?std.Thread,
        const Self = @This();

        const ErasureCoder = erasure.Coder(W);
        const QueueItem = union(enum) {
            file: Upload,

            const Upload = struct {
                ctx: Ctx,
                src: Src,
                full_size: u64,
            };
        };

        // TODO: should this use a more strict memory order?
        const must_stop_store_mo: std.builtin.AtomicOrder = .Monotonic;
        const must_stop_load_mo: std.builtin.AtomicOrder = .Monotonic;

        const RequestUriBuffers = struct {
            gc: []u8,
        };

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

            const request_uris_buf_res = try util.buffer_backed_slices.fromAlloc(RequestUriBuffers, params.allocator, .{
                .gc = if (params.providers.google_cloud) |gc| gc.objectUriIteratorBufferSize() else 0,
            });
            const request_uri_bufs: RequestUriBuffers = request_uris_buf_res[0];
            const full_request_uri_buf = request_uris_buf_res[1];
            errdefer params.allocator.free(full_request_uri_buf);

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

                .full_request_uri_buf = full_request_uri_buf,
                .request_uri_bufs = request_uri_bufs,

                .chunk_buffers = chunk_buffers,

                .random = params.random,
                .ec = ec,
                .thread = null,
            };
        }

        pub inline fn start(self: *Self) std.Thread.SpawnError!void {
            assert(self.thread == null);
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
                .cancel_remaining_uploads => {
                    self.queue_mtx.lock();
                    defer self.queue_mtx.unlock();
                    self.queue.clearItems();
                },
            }

            self.queue_pop_re.set();
            if (self.thread) |thread| thread.join();
            self.queue.deinit(self.allocator);

            self.allocator.destroy(self.chunk_buffers);
            self.allocator.free(self.full_request_uri_buf);

            self.ec.deinit(self.allocator);
        }

        const UploadParams = struct {
            /// The content source. Must be copy-able by value - if it is a pointer
            /// or handle of some sort, it must outlive the pipeline, or it must only
            /// become invalid after being passed to `ctx_ptr.close`.
            /// Must provide `src.seekableStream()` and `src.reader()`.
            src: Src,
            /// Pre-calculated size of the contents; if `null`,
            /// the size will be determined during this function call.
            full_size: ?u64 = null,
        };

        pub fn uploadFile(
            self: *Self,
            ctx_ptr: anytype,
            params: UploadParams,
        ) (std.mem.Allocator.Error || SrcNs.SeekableStream.GetSeekPosError)!void {
            const src = params.src;
            const ctx = Ctx.init(ctx_ptr);

            const full_size: u64 = size: {
                const reported_full_size = params.full_size orelse {
                    break :size try src.seekableStream().getEndPos();
                };
                if (comptime @import("builtin").mode == .Debug) debug_check: {
                    const real_full_size = try src.seekableStream().getEndPos();
                    if (real_full_size == reported_full_size) break :debug_check;
                    const msg = util.boundedFmt(
                        "Given file size '{d}' differs from file size '{d}' obtained from stat",
                        .{ reported_full_size, real_full_size },
                        .{ std.math.maxInt(@TypeOf(reported_full_size)), std.math.maxInt(@TypeOf(real_full_size)) },
                    ) catch unreachable;
                    @panic(msg.constSlice());
                }
                break :size reported_full_size;
            };

            try src.seekableStream().seekTo(0);
            try self.pushToQueue(.{ .file = .{
                .ctx = ctx,
                .src = src,
                .full_size = full_size,
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

            inline fn init(
                /// Must implement the functions:
                /// `fn update(ctx_ptr: @This(), percentage: u8) void`
                /// `fn close(ctx_ptr: @This(), src: Src, stored_file: StoredFile, encryption: chunk.EncryptionInfo) void`
                ctx_ptr: anytype,
            ) Ctx {
                const Ptr = @TypeOf(ctx_ptr);
                const gen = struct {
                    fn actionFn(erased_ptr: *anyopaque, action_data: Ctx.Action) void {
                        const ptr: Ptr = @ptrCast(@alignCast(erased_ptr));
                        switch (action_data) {
                            .update => |percentage| ptr.update(percentage),
                            .close => |args| ptr.close(args.src, args.stored_file),
                        }
                    }
                };
                return .{
                    .ptr = ctx_ptr,
                    .actionFn = gen.actionFn,
                };
            }

            pub inline fn update(self: Ctx, percentage: u8) void {
                return self.action(.{ .update = percentage });
            }

            pub inline fn close(
                self: Ctx,
                src: Src,
                stored_file: ?*const StoredFile,
            ) void {
                return self.action(.{ .close = .{
                    .src = src,
                    .stored_file = stored_file,
                } });
            }

            inline fn action(self: Ctx, data: Action) void {
                return self.actionFn(self.ptr, data);
            }
            pub const Action = union(enum) {
                update: u8,
                close: Close,

                const Close = struct {
                    src: Src,
                    stored_file: ?*const StoredFile,
                };
            };
        };

        fn uploadPipeLineThread(upp: *Self) void {
            var http_client = std.http.Client{ .allocator = upp.allocator };
            defer http_client.deinit();

            const test_key = [_]u8{0xD} ** Aes256Gcm.key_length;
            var nonce_generator: struct {
                counter: u64 = 0,
                random: std.rand.Random,

                inline fn new(this: *@This()) [Aes256Gcm.nonce_length]u8 {
                    var random_bytes: [4]u8 = undefined;
                    this.random.bytes(&random_bytes);
                    defer this.counter +%= 1;
                    return std.mem.toBytes(this.counter) ++ random_bytes;
                }
            } = .{ .random = upp.random };

            const RequestDataBufs = struct { []util.BoundedBufferArray(u8), []u8 };
            var request_data_buf = std.ArrayListAligned(u8, util.buffer_backed_slices.bufferAlignment(RequestDataBufs)).init(upp.allocator);
            defer request_data_buf.deinit();

            while (true) {
                const queue_item: QueueItem = blk: {
                    upp.queue_pop_re.wait();

                    upp.queue_mtx.lock();
                    defer upp.queue_mtx.unlock();

                    break :blk upp.queue.popValue() orelse {
                        upp.queue_pop_re.reset();
                        if (upp.must_stop.load(must_stop_load_mo)) break;
                        continue;
                    };
                };

                const up_data: QueueItem.Upload = switch (queue_item) {
                    .file => |file| file,
                };

                const up_ctx = up_data.ctx;
                const chunk_count = chunk.countForFileSize(up_data.full_size);

                const reader = up_data.src.reader();
                const seeker = up_data.src.seekableStream();

                var stored_file: ?StoredFile = null;

                defer {
                    up_ctx.update(100);
                    up_ctx.close(up_data.src, if (stored_file) |*ptr| ptr else null);
                }

                // `uploadFile` seeks to 0 before pushing the source to the queue,
                // so we assume we're at the start of the source here.
                const full_file_digest = blk: {
                    // although we'll be using the array elements of this buffer later,
                    // we aren't using them yet, so we use the whole thing here first
                    // to hash large amounts of the data at a time.
                    const buffer: *[chunk.total_size * 2]u8 = std.mem.asBytes(upp.chunk_buffers);
                    var full_file_hasher = Sha256.init(.{});

                    while (true) {
                        const byte_len = reader.readAll(buffer) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        const data = buffer[0..byte_len];
                        if (data.len == 0) break;
                        full_file_hasher.update(data);
                    }
                    break :blk full_file_hasher.finalResult();
                };

                var eci = chunk.encryptedChunkIterator(reader, seeker, .{
                    .full_file_digest = full_file_digest,
                    .chunk_count = chunk_count,
                    .buffers = upp.chunk_buffers,
                });

                var bytes_uploaded: u64 = 0;
                _ = bytes_uploaded;
                const upload_size = upp.ec.totalEncodedSize(
                    chunk_count * @as(u64, chunk.Header.size) + up_data.full_size,
                );

                while (true) {
                    const result = eci.next(.{
                        .npub = &nonce_generator.new(),
                        .key = &test_key,
                    }) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    } orelse break;

                    const chunk_name = result.name;
                    const encrypted_chunk_blob = result.encrypted;

                    // the number of bytes that will be sent in each request
                    const shard_upload_size = upp.ec.encodedSizePerShard(encrypted_chunk_blob.len);
                    const shard_upload_size_str = util.boundedFmt(
                        "{d}",
                        .{shard_upload_size},
                        .{std.math.maxInt(@TypeOf(shard_upload_size))},
                    ) catch unreachable;

                    const shard_datas: []util.BoundedBufferArray(u8) = blk: {
                        request_data_buf.clearRetainingCapacity();
                        const shard_datas: []util.BoundedBufferArray(u8), //
                        const upload_data_buf: []u8 = util.buffer_backed_slices.fromArrayList(
                            RequestDataBufs,
                            &request_data_buf,
                            .{ upp.ec.shardCount(), upload_size },
                        ) catch |err| switch (err) {
                            error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                        };

                        for (shard_datas, 0..) |*data, i| {
                            const start_offset = i * shard_upload_size;
                            const data_buf = upload_data_buf[start_offset..][0..shard_upload_size];
                            data.* = .{ .buffer = data_buf };
                        }

                        const writers_ctx: struct {
                            upload_datas: []util.BoundedBufferArray(u8),
                            pub inline fn getWriter(ctx: @This(), writer_idx: u7) util.BoundedBufferArray(u8).Writer {
                                return ctx.upload_datas[writer_idx].writer();
                            }
                        } = .{ .upload_datas = shard_datas };

                        var ecd_fbs = std.io.fixedBufferStream(encrypted_chunk_blob);
                        var write_buffer: [4096]u8 = undefined;
                        _ = upp.ec.encodeCtx(ecd_fbs.reader(), writers_ctx, &write_buffer) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };

                        break :blk shard_datas;
                    };
                    var shard_datas_sent: usize = 0;
                    defer assert(shard_datas_sent == shard_datas.len);

                    if (shard_datas_sent != shard_datas.len) if (upp.providers.google_cloud) |gc| gc_blk: {
                        // the headers are cloned for each request, so can deinitialize this safely
                        var headers = std.http.Headers.init(upp.allocator);
                        defer headers.deinit();
                        headers.owned = false; // since it's cloned anyway, we don't need to clone the values bound to this scope

                        const auth_val = gc.authorizationValue() orelse break :gc_blk;

                        headers.append("Content-Length", shard_upload_size_str.constSlice()) catch |err| @panic(@errorName(err));
                        headers.append("Authorization", auth_val.constSlice()) catch |err| @panic(@errorName(err));

                        var iter = gc.objectUriIterator(chunk_name, upp.request_uri_bufs.gc);
                        while (iter.next()) |uri_str| {
                            if (shard_datas_sent == shard_datas.len) break;
                            const shard_data: []const u8 = shard_datas[shard_datas_sent].slice();
                            shard_datas_sent += 1;

                            const uri = std.Uri.parse(uri_str) catch unreachable;
                            var req = http_client.open(.PUT, uri, headers, .{}) catch |err| switch (err) {
                                error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                                inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                            };
                            defer req.deinit();

                            req.send(.{}) catch |err| switch (err) {
                                inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                            };
                            req.writeAll(shard_data) catch |err| switch (err) {
                                inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                            };
                            req.finish() catch |err| @panic(switch (err) {
                                inline else => |e| "Decide how to handle " ++ @errorName(e),
                            });
                        }
                    };

                    if (shard_datas_sent != shard_datas.len) if (upp.providers.aws) |aws| aws_blk: {
                        const credentials = aws.credentials orelse break :aws_blk;

                        var headers = std.http.Headers.init(upp.allocator);
                        defer headers.deinit();

                        const method: std.http.Method = .PUT;

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

                        var uri_str_buf = std.ArrayList(u8).init(upp.allocator);
                        defer uri_str_buf.deinit();

                        for (aws.buckets) |bucket| {
                            if (shard_datas_sent == shard_datas.len) break;
                            const shard_data: []const u8 = shard_datas[shard_datas_sent].slice();
                            shard_datas_sent += 1;

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

                            const payload_digest = digest: {
                                var shard_digest: [Sha256.digest_length]u8 = undefined;
                                Sha256.hash(shard_data, &shard_digest, .{});
                                break :digest shard_digest;
                            };
                            headers.clearRetainingCapacity();
                            Providers.Aws.http.sortAndAddHeaders(upp.allocator, &headers, .{
                                .request_method = @tagName(method),
                                .request_uri = uri,

                                .date_time = date_time.constSlice(),
                                .service = "s3",
                                .region = region_str.constSlice(),

                                .access_key_id = credentials.access_key_id.getSensitiveSlice(),
                                .secret_access_key = credentials.secret_access_key.getSensitiveSlice(),
                                .session_token = credentials.session_token.getSensitiveSlice(),

                                .payload_sign = .{ .digest = &payload_digest },
                            }) catch |err| @panic(switch (err) {
                                inline else => |e| "Decide how to handle " ++ @errorName(e),
                            });
                            headers.append("content-length", shard_upload_size_str.constSlice()) catch |err| @panic(switch (err) {
                                inline else => |e| "Decide how to handle " ++ @errorName(e),
                            });

                            var req = http_client.open(method, uri, headers, .{}) catch |err| switch (err) {
                                error.OutOfMemory => @panic("TODO: actually handle this scenario in some way that isn't just panicking on this thread"),
                                inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                            };
                            defer req.deinit();
                            req.send(.{ .raw_uri = false }) catch |err| switch (err) {
                                inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                            };
                            req.writeAll(shard_data) catch |err| switch (err) {
                                inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                            };
                            req.finish() catch |err| @panic(switch (err) {
                                inline else => |e| "Decide how to handle " ++ @errorName(e),
                            });
                            req.wait() catch |err| @panic(switch (err) {
                                inline else => |e| "Decide how to handle " ++ @errorName(e),
                            });

                            switch (req.response.status) {
                                .ok => {},
                                else => @panic("TODO: Handle other response statuses"),
                            }
                        }
                    };
                }

                stored_file = eci.storedFile();
            }
        }
    };
}

/// Verify & return the associated namespace of `Src`.
inline fn verifySrcType(comptime Src: type) !type {
    const Ns = Ns: {
        switch (@typeInfo(Src)) {
            .Struct, .Union, .Enum => break :Ns Src,
            .Pointer => |pointer| if (pointer.size == .One)
                switch (@typeInfo(pointer.child)) {
                    .Struct, .Union, .Enum, .Opaque => switch (pointer.child) {
                        else => break :Ns pointer.child,
                        anyopaque => {},
                    },
                    else => {},
                },
            else => {},
        }
        return @field(anyerror, std.fmt.comptimePrint(
            "Expected type or pointer type with a child type with an associated namespace (struct, union, enum, typed opaque pointer), instead got '{s}'",
            .{@typeName(Src)},
        ));
    };

    const ptr_prefix = if (Src == Ns) "" else blk: {
        const info = @typeInfo(Src).Pointer;
        var prefix: []const u8 = "*";
        if (info.is_allowzero) prefix = prefix ++ "allowzero ";
        if (@sizeOf(info.child) != 0 and @alignOf(info.child) != info.alignment) {
            prefix = prefix ++ std.fmt.comptimePrint("align({d})", .{info.alignment});
        }
        if (info.address_space != @typeInfo(*anyopaque).Pointer.address_space) {
            prefix = prefix ++ std.fmt.comptimePrint("addrspace(.{s})", .{std.zig.fmtId(@tagName(info.address_space))});
        }
        if (info.is_const) prefix = prefix ++ "const ";
        if (info.is_volatile) prefix = prefix ++ "volatile ";
        break :blk prefix;
    };
    if (!@hasDecl(Ns, "Reader")) return @field(anyerror, std.fmt.comptimePrint("Expected '{s}' to contain `pub const Reader = std.io.Reader(...);`", .{@typeName(Ns)}));
    if (!@hasDecl(Ns, "reader")) return @field(anyerror, std.fmt.comptimePrint("Expected '{s}' to contain `pub fn reader(self: {s}@This()) Reader {...}`", .{ @typeName(Ns), ptr_prefix }));
    if (!@hasDecl(Ns, "SeekableStream")) return @field(anyerror, std.fmt.comptimePrint("Expected '{s}' to contain `pub const SeekableStream = std.io.SeekableStream(...);`", .{@typeName(Ns)}));
    if (!@hasDecl(Ns, "seekableStream")) return @field(anyerror, std.fmt.comptimePrint("Expected '{s}' to contain `pub fn seekableStream(self: {s}@This()) SeekableStream {...}`", .{ @typeName(Ns), ptr_prefix }));
    return Ns;
}
