const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const eraser = @import("eraser");

pub const std_options = struct {
    pub const log_level: std.log.Level = .debug;
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .thread_safe = true,
        .stack_trace_frames = 32,
    }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var providers_mtx: std.Thread.Mutex = .{};
    var providers = eraser.Providers{
        .google_cloud = .{
            .auth_token = null,
            .bucket_names = &[_][]const u8{
                // "ec1.blocktube.net",
                // "ec2.blocktube.net",
                // "ec3.blocktube.net",
                "ec4.blocktube.net",
                "ec5.blocktube.net",
                "ec6.blocktube.net",
            },
        },

        .aws = .{
            .credentials = null,
            .buckets = &.{
                .{ .region = .{ .geo = "us".*, .cardinal = .east, .number = 2 }, .name = "ec7.blocktube.net" },
                .{ .region = .{ .geo = "us".*, .cardinal = .east, .number = 2 }, .name = "ec8.blocktube.net" },
                .{ .region = .{ .geo = "us".*, .cardinal = .west, .number = 2 }, .name = "ec9.blocktube.net" },
                // .{ .region = .{ .geo = "us".*, .cardinal = .west, .number = 2 }, .name = "ec10.blocktube.net" },
                // .{ .region = .{ .geo = "eu".*, .cardinal = .west, .number = 1 }, .name = "ec11.blocktube.net" },
                // .{ .region = .{ .geo = "eu".*, .cardinal = .west, .number = 1 }, .name = "ec12.blocktube.net" },
            },
        },

        .shards_required = 3,
    };

    var aws_credentials_session_token_buffer = std.ArrayList(u8).init(allocator);
    defer aws_credentials_session_token_buffer.deinit();

    var default_prng = std.rand.DefaultPrng.init(1243);
    var thread_safe_prng = eraser.threadSafeRng(default_prng.random());
    const random = thread_safe_prng.random();

    const FilePReaderSrc = struct {
        file: std.fs.File,
        curr_pos: u64,
        end_pos: u64,

        pub const Reader = std.io.Reader(*@This(), std.fs.File.PReadError, read);
        pub inline fn reader(self: *@This()) Reader {
            return .{ .context = self };
        }
        fn read(self: *@This(), buf: []u8) std.fs.File.PReadError!usize {
            const result = try self.file.pread(buf, self.curr_pos);
            self.curr_pos += result;
            return result;
        }

        pub const SeekableStream = std.io.SeekableStream(
            *@This(),
            error{},
            error{},
            seekTo,
            seekBy,
            getPos,
            getEndPos,
        );
        pub inline fn seekableStream(self: *@This()) SeekableStream {
            return .{ .context = self };
        }
        fn seekBy(self: *@This(), off: i64) error{}!void {
            if (off < 0)
                self.curr_pos -= std.math.absCast(off)
            else
                self.curr_pos += off;
        }
        // zig fmt: off
        fn seekTo(self: *@This(), pos: u64) error{}!void { self.curr_pos = pos; }
        fn getPos(self: *@This()) error{}!u64 { return self.curr_pos; }
        fn getEndPos(self: *@This()) error{}!u64 { return self.end_pos; }
        // zig fmt: on
    };

    var upload_pipeline = try eraser.uploadPipeline(u8, *FilePReaderSrc, .{
        .allocator = allocator,
        .random = random,
        .queue_capacity = 8,
        .providers = &providers,
        .providers_mtx = &providers_mtx,
    });
    defer upload_pipeline.deinit(.finish_remaining_uploads);
    try upload_pipeline.start();

    var download_pipeline = try eraser.downloadPipeLine(u8, std.fs.File.Writer, .{
        .allocator = allocator,
        .random = random,
        .queue_capacity = 8,
        .providers = &providers,
        .providers_mtx = &providers_mtx,
    });
    defer download_pipeline.deinit(.finish_remaining_downloads);
    try download_pipeline.start();

    var line_buffer = std.ArrayList(u8).init(allocator);
    defer line_buffer.deinit();

    var prev_first_chunk_name: ?eraser.StoredFile = null;

    const Command = enum {
        q,
        quit,

        h,
        help,

        encode,
        decode,

        @"auth-aws",
        @"auth-gc",
    };

    std.log.info("Available commands: {s}", .{comptime std.meta.fieldNames(Command)});

    while (true) {
        line_buffer.clearRetainingCapacity();
        try std.io.getStdIn().reader().streamUntilDelimiter(line_buffer.writer(), '\n', 1 << 21);
        var tokenizer = std.mem.tokenizeAny(u8, line_buffer.items, &std.ascii.whitespace);

        const cmd_str = tokenizer.next() orelse {
            std.log.err("Missing command", .{});
            continue;
        };
        assert(cmd_str.len != 0);
        const cmd = std.meta.stringToEnum(Command, cmd_str) orelse {
            std.log.err("Unrecognized command '{}'", .{std.zig.fmtEscapes(cmd_str)});
            continue;
        };
        switch (cmd) {
            .h, .help => {
                std.log.info("Available commands: {s}", .{comptime std.meta.fieldNames(Command)});
                continue;
            },
            .q, .quit => break,
            .encode => {
                const input_path = tokenizer.next() orelse continue;

                std.log.info("Queueing file '{s}' for encoding and upload", .{input_path});

                var progress = std.Progress{};
                const root_node = progress.start("Upload", 100);
                root_node.activate();

                const WaitCtx = struct {
                    progress: *std.Progress.Node,
                    close_re: std.Thread.ResetEvent = .{},
                    stored_file: ?eraser.StoredFile = null,
                    encryption_info: ?eraser.chunk.Encryption = null,

                    pub fn update(self: *@This(), percentage: u8) void {
                        self.progress.setCompletedItems(percentage);
                        self.progress.context.maybeRefresh();
                    }
                    pub fn close(
                        self: *@This(),
                        src: *FilePReaderSrc,
                        stored_file: ?*const eraser.StoredFile,
                    ) void {
                        self.progress.setCompletedItems(100);
                        self.progress.context.maybeRefresh();

                        self.stored_file = if (stored_file) |sf| sf.* else null;

                        src.file.close();
                        self.close_re.set();
                        while (self.close_re.isSet()) {}
                    }
                };

                var wait_ctx = WaitCtx{
                    .progress = root_node,
                };

                {
                    const file = try std.fs.cwd().openFile(input_path, .{});
                    errdefer file.close();

                    var input: FilePReaderSrc = FilePReaderSrc{
                        .file = file,
                        .curr_pos = 0,
                        .end_pos = try file.getEndPos(),
                    };

                    try upload_pipeline.uploadFile(&wait_ctx, .{
                        .src = &input,
                        .full_size = null,
                    });

                    wait_ctx.close_re.wait();
                    root_node.end();
                    wait_ctx.close_re.reset();
                }

                const stored_file = wait_ctx.stored_file orelse {
                    std.log.err("Failed to fully encode file", .{});
                    continue;
                };
                prev_first_chunk_name = stored_file;

                std.log.info("Finished encoding '{s}', first chunk name: {s}", .{
                    input_path,
                    eraser.digestBytesToString(&stored_file.first_name),
                });
            },
            .decode => {
                const stored_file: eraser.StoredFile = sf: {
                    const first_chunk_name: [Sha256.digest_length]u8 = name: {
                        const first_digest = tokenizer.next() orelse break :sf prev_first_chunk_name orelse {
                            std.log.err("No files uploaded this session", .{});
                            continue;
                        };
                        const digest_str_len = Sha256.digest_length * 2;
                        if (first_digest.len != digest_str_len) {
                            std.log.err("Expected digest string ({d} bytes), found '{}' ({d} bytes)", .{
                                digest_str_len,
                                std.zig.fmtEscapes(first_digest),
                                first_digest.len,
                            });
                            continue;
                        }
                        break :name eraser.digestStringToBytes(first_digest[0..digest_str_len]) catch |err| {
                            std.log.err("({s}) Invalid digest string '{}', must be a sequence of two digit hex codes", .{
                                @errorName(err),
                                std.zig.fmtEscapes(first_digest),
                            });
                            continue;
                        };
                    };
                    const chunk_count_str = tokenizer.next() orelse {
                        std.log.err("Expected first chunk name followed by chunk count", .{});
                        continue;
                    };
                    const chunk_count = std.fmt.parseInt(eraser.chunk.Count, chunk_count_str, 10) catch |err| {
                        std.log.err("({s}) Expected chunk count, found '{}'", .{
                            @errorName(err),
                            std.zig.fmtEscapes(chunk_count_str),
                        });
                        continue;
                    };
                    break :sf eraser.StoredFile{
                        .encryption = @panic("TODO"),
                        .first_name = first_chunk_name,
                        .chunk_count = chunk_count,
                    };
                };

                var progress = std.Progress{};
                const root_node = progress.start("Upload", 100);
                root_node.activate();

                const WaitCtx = struct {
                    progress: *std.Progress.Node,
                    close_re: std.Thread.ResetEvent = .{},

                    pub fn update(self: *@This(), percentage: u8) void {
                        self.progress.setCompletedItems(percentage);
                        self.progress.context.maybeRefresh();
                    }
                    pub fn close(self: *@This(), dst: std.fs.File.Writer) void {
                        _ = dst;
                        self.close_re.set();
                        while (self.close_re.isSet()) {}
                    }
                };

                var wait_ctx = WaitCtx{
                    .progress = root_node,
                };

                const output_file = try std.fs.cwd().createFile("decoded", .{});
                defer output_file.close();

                try download_pipeline.downloadFile(&wait_ctx, .{
                    .writer = output_file.writer(),
                    .stored_file = &stored_file,
                });

                wait_ctx.close_re.wait();
                root_node.end();
                wait_ctx.close_re.reset();
            },
            .@"auth-gc" => {
                const auth_token = tokenizer.next() orelse {
                    std.log.err("Missing auth token", .{});
                    continue;
                };
                const auth_tok_bounded = eraser.SensitiveBytes.Bounded(eraser.Providers.GoogleCloud.max_auth_token_len).init(auth_token) orelse {
                    std.log.err("Bad auth token", .{});
                    continue;
                };

                providers_mtx.lock();
                defer providers_mtx.unlock();

                const gcloud: *eraser.Providers.GoogleCloud = if (providers.google_cloud) |*gcloud| gcloud else {
                    std.log.err("Google cloud is not enabled as a provider", .{});
                    continue;
                };
                gcloud.auth_token = auth_tok_bounded;
            },
            .@"auth-aws" => {
                const Aws = eraser.Providers.Aws;

                const access_key_id: []const u8 = tokenizer.next() orelse {
                    std.log.err("Missing access key id", .{});
                    continue;
                };
                const secret_access_key: []const u8 = tokenizer.next() orelse {
                    std.log.err("Missing secret access key", .{});
                    continue;
                };
                const session_token: []const u8 = sess: {
                    const session_token = tokenizer.next() orelse {
                        std.log.err("Missing session token", .{});
                        continue;
                    };
                    aws_credentials_session_token_buffer.clearRetainingCapacity();
                    const copied = try aws_credentials_session_token_buffer.addManyAsSlice(session_token.len);
                    @memcpy(copied, session_token);
                    break :sess copied;
                };
                const new_creds = .{
                    .access_key_id = eraser.SensitiveBytes.Fixed(Aws.auth.access_key_id_len).init(access_key_id) orelse {
                        std.log.err("Bad access key id", .{});
                        continue;
                    },
                    .secret_access_key = eraser.SensitiveBytes.Fixed(Aws.auth.secret_access_key_len).init(secret_access_key) orelse {
                        std.log.err("Bad access key id", .{});
                        continue;
                    },
                    .session_token = eraser.SensitiveBytes.init(session_token),
                };

                providers_mtx.lock();
                defer providers_mtx.unlock();
                const aws: *Aws = if (providers.aws) |*aws| aws else {
                    std.log.err("AWS is not enabled as a provider", .{});
                    continue;
                };
                aws.credentials = new_creds;
            },
        }
    }
}
