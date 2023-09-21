const chunk = @import("chunk.zig");
const erasure = @import("../erasure.zig");
const PipelineInitValues = @import("PipelineInitValues.zig");
const ServerInfo = @import("ServerInfo.zig");
const SharedQueue = @import("../shared_queue.zig").SharedQueue;
const StoredFile = @import("upload.zig").StoredFile;

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
        stored_file: StoredFile,
        encryption_info: chunk.EncryptionInfo,
    };

    pub inline fn init(data: Data, ctx_ptr: anytype) Ctx {
        const Ptr = @TypeOf(ctx_ptr);
        const gen = struct {
            fn actionFn(erased_ptr: *anyopaque, action_data: Ctx.Action) void {
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

    pub inline fn update(self: Ctx, percentage: u8) void {
        return self.action(.{ .update = percentage });
    }

    pub inline fn close(self: Ctx) void {
        return self.action(.{ .close = {} });
    }

    inline fn action(self: Ctx, data: Action) void {
        return self.actionFn(self.ptr, data);
    }

    pub const Action = union(enum) {
        /// percentage of progress
        update: u8,
        close,
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

        chunk_buffer: *[header_plus_chunk_max_size * 2]u8,

        random: std.rand.Random,
        ec: ErasureCoder,
        thread: std.Thread,
        const Self = @This();

        const header_plus_chunk_max_size = chunk.size + chunk.max_header_size;

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
            assert(values.queue_capacity != 0);

            self.* = .{
                .allocator = allocator,
                .requests_buf = &.{},
                .server_info = values.server_info,
                .gc_prealloc = null,

                .must_stop = std.atomic.Atomic(bool).init(false),
                .queue_mtx = .{},
                .queue = undefined,

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

            self.allocator.free(self.chunk_buffer);

            self.ec.deinit(self.allocator);
            self.allocator.free(self.requests_buf);
            if (self.gc_prealloc) |pre_alloc| pre_alloc.deinit(self.allocator);
        }

        pub fn downloadFile(
            self: *Self,
            stored_file: *const StoredFile,
            encryption_info: *const chunk.EncryptionInfo,
            ctx_ptr: anytype,
        ) !void {
            const data = Ctx.Data{
                .stored_file = stored_file.*,
                .encryption_info = encryption_info.*,
            };
            _ = try self.queue.pushValue(self.allocator, Ctx.init(data, ctx_ptr));
        }

        fn downloadPipeLineThread(dpp: *Self) void {
            var client = std.http.Client{ .allocator = dpp.allocator };
            defer client.deinit();

            const decrypted_chunk_buffer: *[header_plus_chunk_max_size]u8 = dpp.chunk_buffer[header_plus_chunk_max_size * 0 ..][0..header_plus_chunk_max_size];
            const encrypted_chunk_buffer: *[header_plus_chunk_max_size]u8 = dpp.chunk_buffer[header_plus_chunk_max_size * 1 ..][0..header_plus_chunk_max_size];

            while (true) {
                const down_ctx: Ctx = dpp.queue.popValue() orelse {
                    if (dpp.must_stop.load(must_stop_load_mo)) break;
                    std.atomic.spinLoopHint();
                    continue;
                };
                const down_data = down_ctx.data;
                defer down_ctx.close();

                const excluded_index_set = erasure.sampleIndexSet(
                    dpp.random,
                    dpp.ec.shardCount(),
                    dpp.ec.shardCount() - dpp.ec.shardsRequired(),
                );

                var maybe_file: ?std.fs.File = null;
                defer if (maybe_file) |file| file.close();

                var next_encryption_info = down_data.encryption_info;
                var current_chunk_name: ?[Sha256.digest_length]u8 = down_data.stored_file.first_name;

                var chunks_encountered: chunk.Count = 0;
                while (current_chunk_name) |chunk_name| {
                    if (chunks_encountered == down_data.stored_file.chunk_count) {
                        @panic("TODO handle: more chunks encountered than specified");
                    }
                    chunks_encountered += 1;
                    var requests = util.BoundedBufferArray(std.http.Client.Request){ .buffer = dpp.requests_buf };
                    defer for (requests.slice()) |*req| req.deinit();

                    { // populate `requests`
                        var current_index: u8 = 0;

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

                    var ecd_fbs = std.io.fixedBufferStream(encrypted_chunk_buffer);
                    _ = dpp.ec.decodeCtx(excluded_index_set, ecd_fbs.writer(), readers_ctx) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        inline error.NoSpaceLeft => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                    const encrypted_blob_data: []const u8 = ecd_fbs.getWritten();

                    const auth_tag = next_encryption_info.tag;
                    const npub = next_encryption_info.npub;
                    const key = next_encryption_info.key;
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
                    var fbs = std.io.fixedBufferStream(decrypted_blob_data);

                    const header = chunk.readHeader(fbs.reader()) catch |err| switch (err) {
                        inline //
                        error.EndOfStream,
                        error.UnrecognizedHeaderVersion,
                        error.InvalidFirstChunkFlag,
                        => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                    assert(header.byteCount() == fbs.pos);
                    const decrypted_chunk_data = decrypted_blob_data[header.byteCount()..];

                    current_chunk_name, next_encryption_info = if (header.next) |next|
                        .{ next.chunk_blob_digest, next.encryption }
                    else
                        .{ null, undefined };

                    const file = maybe_file orelse blk: {
                        const file = std.fs.cwd().createFile("decoded", .{}) catch |err| switch (err) {
                            inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                        };
                        maybe_file = file;
                        break :blk file;
                    };
                    file.writeAll(decrypted_chunk_data) catch |err| switch (err) {
                        inline else => |e| @panic("Decide how to handle " ++ @errorName(e)),
                    };
                }
            }
        }
    };
}
