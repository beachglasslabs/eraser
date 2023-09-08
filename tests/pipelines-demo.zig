const std = @import("std");
const assert = std.debug.assert;
const Sha256 = std.crypto.hash.sha2.Sha256;

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

    var upload_pipeline: eraser.UploadPipeLine(u8) = undefined;
    try upload_pipeline.init(allocator, pipeline_values);
    defer upload_pipeline.deinit(.finish_remaining_uploads);

    var default_prng = std.rand.DefaultPrng.init(1243);
    var download_pipeline: eraser.DownloadPipeLine(u8) = undefined;
    try download_pipeline.init(allocator, default_prng.random(), pipeline_values);
    defer download_pipeline.deinit(.finish_remaining_uploads);

    var line_buffer = std.ArrayList(u8).init(allocator);
    defer line_buffer.deinit();

    const ChunkDigests = std.BoundedArray([Sha256.digest_length]u8, 6);
    var last_chunk_digests: ?ChunkDigests = null;

    while (true) {
        line_buffer.clearRetainingCapacity();
        try std.io.getStdIn().reader().streamUntilDelimiter(line_buffer.writer(), '\n', 1 << 21);
        var tokenizer = std.mem.tokenizeAny(u8, line_buffer.items, &std.ascii.whitespace);

        const cmd = tokenizer.next() orelse {
            std.log.err("Missing command", .{});
            continue;
        };
        assert(cmd.len != 0);
        if (std.mem.startsWith(u8, "quit", cmd)) break; // all of "quit", "qui", "qu", "q" are treated the same

        if (std.mem.eql(u8, cmd, "encode")) {
            const input_path = tokenizer.next() orelse continue;

            std.log.err("Queueing file '{s}' for encoding and upload", .{input_path});
            const input = try std.fs.cwd().openFile(input_path, .{});
            errdefer input.close();

            var progress = std.Progress{};
            const root_node = progress.start("Upload", 100);
            root_node.activate();

            const WaitCtx = struct {
                progress: *std.Progress.Node,
                close_re: std.Thread.ResetEvent = .{},
                chunks: ?ChunkDigests = null,

                pub inline fn update(self: *@This(), percentage: u8) void {
                    self.progress.setCompletedItems(percentage);
                    self.progress.context.maybeRefresh();
                }
                pub inline fn close(self: *@This(), file: std.fs.File, chunks: ?[]const [Sha256.digest_length]u8) void {
                    self.progress.setCompletedItems(100);
                    self.progress.context.maybeRefresh();
                    if (chunks) |list| {
                        self.chunks = ChunkDigests.fromSlice(list) catch |err| @panic(@errorName(err));
                    }
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

            const chunks = wait_ctx.chunks orelse {
                std.log.err("Failed to fully encode file", .{});
                continue;
            };

            std.log.info("Finished encoding '{s}' into chunks:", .{input_path});
            for (chunks.constSlice()) |*name| {
                std.log.info("{s}", .{&eraser.digestBytesToString(name)});
            }
            last_chunk_digests = chunks;
        } else if (std.mem.eql(u8, cmd, "decode")) {
            const WaitCtx = struct {
                pub fn close(self: *@This()) void {
                    _ = self;
                }
            };

            var wait_ctx = WaitCtx{};

            const inputs: ChunkDigests = blk: {
                const first_digest = tokenizer.next() orelse {
                    break :blk last_chunk_digests orelse {
                        std.log.err("No files uploaded this session", .{});
                        continue;
                    };
                };
                _ = first_digest;
                @panic("TODO");
            };
            try download_pipeline.downloadFile(inputs.constSlice(), &wait_ctx);
        } else {
            std.log.err("Unrecognized command '{s}'", .{cmd});
        }
    }
}
