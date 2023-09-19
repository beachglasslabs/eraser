const chunk = @import("chunk.zig");
const erasure = @import("../erasure.zig");
const PipelineInitValues = @import("PipelineInitValues.zig");
const ServerInfo = @import("ServerInfo.zig");
const SharedQueue = @import("../shared_queue.zig").SharedQueue;

const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

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
                    .close => |close_data| ptr.close(close_data.file, close_data.digests, close_data.first_encryption),
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
    pub inline fn close(
        self: Ctx,
        digests: ?[]const [Sha256.digest_length]u8,
        first_encryption: ?*const chunk.EncryptionInfo,
    ) void {
        return self.action(.{ .close = .{
            .file = self.data.file,
            .digests = digests,
            .first_encryption = first_encryption,
        } });
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

        const Close = struct {
            file: std.fs.File,
            digests: ?[]const [Sha256.digest_length]u8,
            first_encryption: ?*const chunk.EncryptionInfo,
        };
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
        chunk_buffer: *[header_plus_chunk_max_size * 2]u8,

        random: std.rand.Random,
        ec: ErasureCoder,
        thread: std.Thread,
        const Self = @This();

        const header_plus_chunk_max_size = chunk.size + chunk.max_header_size;

        const ErasureCoder = erasure.Coder(W);
        const ChunkHeaderInfo = struct { header: chunk.Header, chunk_name: [Sha256.digest_length]u8 };

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
                .chunk_buffer = undefined,

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

            self.queue = try SharedQueue(Ctx).initCapacity(&self.queue_mtx, self.allocator, values.queue_capacity);
            errdefer self.queue.deinit(self.allocator);

            self.chunk_buffer = try allocator.create([header_plus_chunk_max_size * 2]u8);
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

            const hpcms = header_plus_chunk_max_size;
            const decrypted_chunk_buffer: *[hpcms]u8 = upp.chunk_buffer[hpcms * 0 ..][0..hpcms];
            const encrypted_chunk_buffer: *[hpcms]u8 = upp.chunk_buffer[hpcms * 1 ..][0..hpcms];

            const test_key = [_]u8{0xD} ** Aes256Gcm.key_length;

            const NonceGenerator = struct {
                counter: u64 = 0,
                random: std.rand.Random,

                inline fn new(this: *@This()) [Aes256Gcm.nonce_length]u8 {
                    const counter_value = this.counter;
                    this.counter +%= 1;
                    var random_bytes: [4]u8 = undefined;
                    this.random.bytes(&random_bytes);
                    return std.mem.toBytes(counter_value) ++ random_bytes;
                }
            };
            var nonce_generator = NonceGenerator{ .random = upp.random };

            while (true) {
                const up_ctx: Ctx = upp.queue.popValue() orelse {
                    if (upp.must_stop.load(must_stop_load_mo)) break;
                    std.atomic.spinLoopHint();
                    continue;
                };
                const up_data = up_ctx.data;
                const chunk_count = chunk.countForFileSize(up_data.file_size);
                var first_encryption: ?chunk.EncryptionInfo = .{
                    .auth_tag = undefined,
                    .npub = nonce_generator.new(),
                    .key = test_key,
                };
                defer {
                    up_ctx.update(100);

                    upp.chunk_headers_buf_mtx.lock();
                    defer upp.chunk_headers_buf_mtx.unlock();
                    const digests = upp.chunk_headers_buf.items(.chunk_name);
                    assert(digests.len <= chunk_count);
                    up_ctx.close(
                        if (digests.len == chunk_count) digests else null,
                        if (first_encryption) |*ptr| ptr else null,
                    );
                }

                // clear chunk header buffer
                // NOTE: this should be safe as the `len` field is never touched by the other thread,
                // and this doesn't touch the capacity, which is only ever touched by the other thread.
                upp.chunk_headers_buf.shrinkRetainingCapacity(0);

                { // first step of chunk headers initialisation
                    var full_hasher = Sha256.init(.{});

                    up_data.file.seekTo(0) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                    var real_chunk_count: chunk.Count = 0;
                    while (true) {
                        const chunk_buffer: *[chunk.size]u8 = upp.chunk_buffer[chunk.max_header_size..][0..chunk.size];
                        const bytes_read = up_data.file.readAll(chunk_buffer) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        const chunk_data = chunk_buffer[0..bytes_read];
                        if (chunk_data.len == 0) break;

                        real_chunk_count += 1;

                        full_hasher.update(chunk_data);
                        const chunk_digest = sha: {
                            var chunk_sha: [Sha256.digest_length]u8 = undefined;
                            Sha256.hash(chunk_data, &chunk_sha, .{});
                            break :sha chunk_sha;
                        };

                        upp.chunk_headers_buf_mtx.lock();
                        defer upp.chunk_headers_buf_mtx.unlock();

                        upp.chunk_headers_buf.appendAssumeCapacity(ChunkHeaderInfo{
                            .header = chunk.Header{
                                .current_chunk_digest = chunk_digest,
                                .next_chunk_blob_digest = undefined,
                                .ordered_data = .{ .middle = .{
                                    .next_encryption = .{
                                        .auth_tag = undefined,
                                        .npub = undefined,
                                        .key = undefined,
                                    },
                                } },
                            },
                            .chunk_name = undefined,
                        });
                    }
                    switch (std.math.order(real_chunk_count, chunk_count)) {
                        .eq => {},
                        .lt => @panic("TODO handle: fewer chunks present than reported"),
                        .gt => @panic("TODO handle: more chunks present than reported"),
                    }

                    const full_file_digest = full_hasher.finalResult();

                    upp.chunk_headers_buf_mtx.lock();
                    defer upp.chunk_headers_buf_mtx.unlock();

                    const headers: []chunk.Header = upp.chunk_headers_buf.items(.header);
                    assert(headers.len != 0);

                    // fully initialise the last chunk header
                    const last = &headers[headers.len - 1];
                    last.* = .{
                        .version = last.version,
                        .current_chunk_digest = last.current_chunk_digest,
                        .next_chunk_blob_digest = last.current_chunk_digest,
                        .ordered_data = .{ .last = .{} },
                    };

                    // partially initialise the first chunk header
                    // if the first and last headers are the same, this doesn't overwrite any important data
                    // or cause any conflicts, it only overwrites
                    // `ordered_data = .{ .last = .{} }` with
                    // `ordered_data = .{ .first = .{...} }`
                    headers[0].ordered_data = .{
                        .first = .{
                            .full_file_digest = full_file_digest,
                            .next_encryption = undefined,
                        },
                    };
                }
                assert(upp.chunk_headers_buf.len == chunk_count);

                var bytes_uploaded: u64 = 0;
                for (1 + 0..1 + chunk_count) |rev_chunk_idx_uncasted| {
                    const chunk_idx: chunk.Count = @intCast(chunk_count - rev_chunk_idx_uncasted);
                    const chunk_offset = chunk.startOffset(chunk_idx);

                    const current_header: chunk.Header = blk: {
                        upp.chunk_headers_buf_mtx.lock();
                        defer upp.chunk_headers_buf_mtx.unlock();

                        const headers = upp.chunk_headers_buf.items(.header);
                        break :blk headers[chunk_idx];
                    };

                    const header_byte_size = blk: {
                        var decrypted_fbs = std.io.fixedBufferStream(decrypted_chunk_buffer);
                        const header_byte_size = chunk.writeHeader(decrypted_fbs.writer(), &current_header) catch |err| switch (err) {
                            error.NoSpaceLeft => unreachable,
                        };
                        assert(decrypted_fbs.pos == header_byte_size);
                        assert(decrypted_fbs.pos <= chunk.max_header_size);
                        break :blk header_byte_size;
                    };

                    // the entire unencrypted header bytes and data bytes of the current block
                    const decrypted_chunk_blob: []const u8 = blk: {
                        const buffer_subsection = decrypted_chunk_buffer[header_byte_size..][0..chunk.size];
                        const bytes_len = up_data.file.preadAll(buffer_subsection, chunk_offset) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        break :blk decrypted_chunk_buffer[0 .. header_byte_size + bytes_len];
                    };

                    var auth_tag: [Aes256Gcm.tag_length]u8 = undefined;
                    const npub = nonce_generator.new();

                    Aes256Gcm.encrypt(
                        encrypted_chunk_buffer[0..decrypted_chunk_blob.len],
                        &auth_tag,
                        decrypted_chunk_blob,
                        "",
                        npub,
                        test_key,
                    );
                    const encrypted_chunk_blob: []const u8 = encrypted_chunk_buffer[0..decrypted_chunk_blob.len];

                    const chunk_name = blk: {
                        var chunk_name: [Sha256.digest_length]u8 = undefined;
                        Sha256.hash(encrypted_chunk_blob, &chunk_name, .{});
                        break :blk chunk_name;
                    };

                    {
                        upp.chunk_headers_buf_mtx.lock();
                        defer upp.chunk_headers_buf_mtx.unlock();

                        const slice = upp.chunk_headers_buf.slice();
                        const chunk_names: [][Sha256.digest_length]u8 = slice.items(.chunk_name);
                        chunk_names[chunk_idx] = chunk_name;

                        if (chunk_idx != 0) { // initialise the `next_chunk_blob_digest` field of the previous chunk (it is the next in the iteration order)
                            const headers: []chunk.Header = slice.items(.header);
                            headers[chunk_idx - 1].next_chunk_blob_digest = chunk_name;
                            continue;
                        }
                    }

                    // should be done after this
                    first_encryption = .{
                        .auth_tag = auth_tag,
                        .npub = npub,
                        .key = test_key,
                    };

                    // TODO: append & send requests
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

                    for (requests.slice()) |*req| req.start() catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };

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

                    var ecd_fbs = std.io.fixedBufferStream(encrypted_chunk_blob);
                    _ = upp.ec.encodeCtx(ecd_fbs.reader(), writers_ctx) catch |err| switch (err) {
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
                }
            }
        }
    };
}
