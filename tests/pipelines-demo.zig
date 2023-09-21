const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;

const eraser = @import("eraser");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{
        .thread_safe = true,
    }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const gc_auth_token = try std.process.getEnvVarOwned(allocator, "ZIG_TEST_GOOGLE_CLOUD_AUTH_KEY");
    defer allocator.free(gc_auth_token);

    const server_info = eraser.ServerInfo{
        .google_cloud = .{
            .auth_token = eraser.SensitiveBytes.init(gc_auth_token),
            .bucket_names = &[_][]const u8{
                "ec1.blocktube.net",
                "ec2.blocktube.net",
                "ec3.blocktube.net",
                "ec4.blocktube.net",
                "ec5.blocktube.net",
                "ec6.blocktube.net",
            },
        },
        .shard_size = 3,
    };

    const pipeline_values = eraser.PipelineInitValues{
        .queue_capacity = 8,
        .server_info = server_info,
    };

    var default_prng1 = std.rand.DefaultPrng.init(1243);
    var default_prng2 = std.rand.DefaultPrng.init(1243);

    var upload_pipeline: eraser.UploadPipeLine(u8) = undefined;
    try upload_pipeline.init(allocator, default_prng1.random(), pipeline_values);
    defer upload_pipeline.deinit(.finish_remaining_uploads);

    var download_pipeline: eraser.DownloadPipeLine(u8) = undefined;
    try download_pipeline.init(allocator, default_prng2.random(), pipeline_values);
    defer download_pipeline.deinit(.finish_remaining_uploads);

    var line_buffer = std.ArrayList(u8).init(allocator);
    defer line_buffer.deinit();

    var last_first_chunk_name: ?eraser.StoredFile = null;
    var last_encryption_info: ?eraser.chunk.EncryptionInfo = null;

    while (true) {
        line_buffer.clearRetainingCapacity();
        try std.io.getStdIn().reader().streamUntilDelimiter(line_buffer.writer(), '\n', 1 << 21);
        var tokenizer = std.mem.tokenizeAny(u8, line_buffer.items, &std.ascii.whitespace);

        const Command = enum {
            help,
            q,
            quit,

            encode,
            decode,
        };
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
            .help => {
                std.log.err("TODO: implement help cmd", .{});
                continue;
            },
            .q, .quit => break,
            .encode => {
                const input_path = tokenizer.next() orelse continue;

                std.log.info("Queueing file '{s}' for encoding and upload", .{input_path});
                const input = try std.fs.cwd().openFile(input_path, .{});
                errdefer input.close();

                var progress = std.Progress{};
                const root_node = progress.start("Upload", 100);
                root_node.activate();

                const WaitCtx = struct {
                    progress: *std.Progress.Node,
                    close_re: std.Thread.ResetEvent = .{},
                    stored_file: ?eraser.StoredFile = null,
                    encryption_info: ?eraser.chunk.EncryptionInfo = null,

                    pub fn update(self: *@This(), percentage: u8) void {
                        self.progress.setCompletedItems(percentage);
                        self.progress.context.maybeRefresh();
                    }
                    pub fn close(
                        self: *@This(),
                        file: std.fs.File,
                        stored_file: ?*const eraser.StoredFile,
                        encryption_info: ?*const eraser.chunk.EncryptionInfo,
                    ) void {
                        self.progress.setCompletedItems(100);
                        self.progress.context.maybeRefresh();

                        self.stored_file = if (stored_file) |sf| sf.* else null;
                        self.encryption_info = if (encryption_info) |ptr| ptr.* else null;

                        file.close();
                        self.close_re.set();
                        while (self.close_re.isSet()) {}
                    }
                };
                var wait_ctx = WaitCtx{
                    .progress = root_node,
                };

                try upload_pipeline.uploadFile(input, &wait_ctx, .{
                    .file_size = null,
                });
                wait_ctx.close_re.wait();
                root_node.end();
                wait_ctx.close_re.reset();

                const stored_file = wait_ctx.stored_file orelse {
                    std.log.err("Failed to fully encode file", .{});
                    continue;
                };
                last_first_chunk_name = stored_file;
                last_encryption_info = wait_ctx.encryption_info orelse @panic("How?");

                std.log.info("Finished encoding '{s}', first chunk name: {s}", .{
                    input_path,
                    eraser.digestBytesToString(&stored_file.first_name),
                });
            },
            .decode => {
                const encryption_info: eraser.chunk.EncryptionInfo = blk: {
                    const first_tok = tokenizer.next() orelse {
                        break :blk last_encryption_info orelse {
                            std.log.err("No files uploaded this session", .{});
                            continue;
                        };
                    };
                    _ = first_tok;
                    @panic("TODO");
                };
                const stored_file: eraser.StoredFile = sf: {
                    const first_chunk_name: [Sha256.digest_length]u8 = name: {
                        const first_digest = tokenizer.next() orelse break :sf last_first_chunk_name orelse {
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
                    pub fn close(self: *@This()) void {
                        _ = self;
                    }
                };

                var wait_ctx = WaitCtx{
                    .progress = root_node,
                };

                try download_pipeline.downloadFile(&stored_file, &encryption_info, &wait_ctx);
            },
        }
    }
}
