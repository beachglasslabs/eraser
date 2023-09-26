const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    // build options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const difftest_file_paths = b.option([]const []const u8, "dt", "List of paths of inputs to test") orelse &.{};

    const shard_count = b.option([]const u8, "shard-count", "Erasure shard count to specify for executables and tests");
    const shards_required = b.option([]const u8, "shards-required", "Erasure shard size to specify for executables and tests");
    const word_size = b.option([]const u8, "word-size", "Erasure word size to specify for executables and tests");
    const confirm_clear_buckets = b.option(bool, "clear-buckets", "Confirm clearing all buckets of all objects (FOR TESTING PURPOSES ONLY).");

    // top level steps
    const run_step = b.step("run", "Run the app");
    const unit_test_step = b.step("unit-test", "Run library tests");
    const difftest_step = b.step("diff-test", "Test for correct behaviour of the executable in encoding and decoding inputs specified via '-Ddt=[path]'");
    const run_libtest_step = b.step("pipeline-demo", "Run the library test executable");
    const clear_buckets_step = b.step("clear-buckets", "Clear all buckets of all objects (INVOKES `gcloud`, FOR TESTING PURPOSES ONLY).");

    // everything else

    const eraser_mod = b.addModule("eraser", .{
        .source_file = Build.LazyPath.relative("src/pipelines.zig"),
    });

    const exe = b.addExecutable(.{
        .name = "eraser",
        .root_source_file = Build.LazyPath.relative("tests/erasure-demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    run_exe.has_side_effects = true; // tell zig we want to run this every time
    run_exe.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_exe.addArgs(args);
    run_step.dependOn(&run_exe.step);

    const unit_tests_exe = b.addTest(.{
        .root_source_file = Build.LazyPath.relative("src/pipelines.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests_run = b.addRunArtifact(unit_tests_exe);
    unit_test_step.dependOn(&unit_tests_run.step);

    for (difftest_file_paths) |file_path| {
        const input = Build.LazyPath.relative(file_path);
        const output = encodeAndDecode(b, exe, input, .{
            .n = shard_count,
            .k = shards_required,
            .w = word_size,
        });

        const difftest_exe = b.addTest(.{
            .name = b.fmt("difftest__{s}", .{std.fs.path.basename(file_path)}),
            .root_source_file = Build.LazyPath.relative("tests/difftest.zig"),
            .target = target,
            .optimize = optimize,
        });
        const paths = b.addOptions();
        difftest_exe.addOptions("paths", paths);
        paths.addOptionPath("input", input);
        paths.addOptionPath("output", output);

        const run_difftest_exe = b.addRunArtifact(difftest_exe);
        difftest_step.dependOn(&run_difftest_exe.step);
    }

    const libtest_exe = b.addExecutable(.{
        .name = "pipelines-demo",
        .root_source_file = Build.LazyPath.relative("tests/pipelines-demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(libtest_exe);
    libtest_exe.addModule("eraser", eraser_mod);

    const libtest_run = b.addRunArtifact(libtest_exe);
    run_libtest_step.dependOn(&libtest_run.step);
    libtest_run.stdio = .inherit;

    if (b.option([]const u8, "gc-auth-key", "Google cloud auth key")) |auth_key| {
        libtest_run.setEnvironmentVariable("ZIG_TEST_GOOGLE_CLOUD_AUTH_KEY", auth_key);
    }

    clear_buckets_step.dependOn(step: {
        if (!(confirm_clear_buckets orelse false))
            break :step failureStep(b, error.FailedToConfirm, "Must specify `-Dclear-buckets` to confirm running step `clear-buckets`");

        const clear_buckets_exe = b.addExecutable(.{
            .name = "clear-buckets",
            .root_source_file = Build.LazyPath.relative("scripts/clear-buckets.zig"),
            .optimize = optimize,
        });
        const clear_buckets_run = b.addRunArtifact(clear_buckets_exe);
        break :step &clear_buckets_run.step;
    });
}

inline fn encodeAndDecode(
    b: *Build,
    eraser_artifact: *Build.CompileStep,
    input: Build.LazyPath,
    options: struct {
        n: ?[]const u8 = null,
        k: ?[]const u8 = null,
        w: ?[]const u8 = null,
    },
) Build.LazyPath {
    // encode
    const run_exe_difftest_encode = b.addRunArtifact(eraser_artifact);
    run_exe_difftest_encode.addArg("encode");

    run_exe_difftest_encode.addArg("--data");
    run_exe_difftest_encode.addFileArg(input);

    run_exe_difftest_encode.addArg("--code");
    const difftest_output_dir = run_exe_difftest_encode.addOutputFileArg("output");

    if (options.n) |n| {
        run_exe_difftest_encode.addArg("-n");
        run_exe_difftest_encode.addArg(n);
    }
    if (options.k) |k| {
        run_exe_difftest_encode.addArg("-k");
        run_exe_difftest_encode.addArg(k);
    }
    if (options.w) |w| {
        run_exe_difftest_encode.addArg("-w");
        run_exe_difftest_encode.addArg(w);
    }

    // decode
    const run_exe_difftest_decode = b.addRunArtifact(eraser_artifact);
    run_exe_difftest_decode.addArg("decode");

    run_exe_difftest_decode.addArg("--data");
    const output = run_exe_difftest_decode.addOutputFileArg("output.txt");

    run_exe_difftest_decode.addArg("--code");
    run_exe_difftest_decode.addDirectoryArg(difftest_output_dir);

    if (options.n) |n| {
        run_exe_difftest_decode.addArg("-n");
        run_exe_difftest_decode.addArg(b.fmt("{d}", .{n}));
    }
    if (options.k) |k| {
        run_exe_difftest_decode.addArg("-k");
        run_exe_difftest_decode.addArg(b.fmt("{d}", .{k}));
    }
    if (options.w) |w| {
        run_exe_difftest_decode.addArg("-w");
        run_exe_difftest_decode.addArg(w);
    }

    return output;
}

fn failureStep(
    b: *Build,
    err: anyerror,
    msg: []const u8,
) *Build.Step {
    const log = std.log.default;
    const msg_duped = b.dupe(msg);

    const FailStep = struct {
        step: Build.Step,
        msg: []const u8,
        err: anyerror,

        fn make(step: *Build.Step, _: *std.Progress.Node) anyerror!void {
            const failure = @fieldParentPtr(@This(), "step", step);
            log.err("{s}", .{failure.msg});
            return failure.err;
        }
    };

    const failure: *FailStep = b.allocator.create(FailStep) catch |e| @panic(@errorName(e));
    failure.* = .{
        .step = Build.Step.init(.{
            .id = .custom,
            .name = b.fmt("Failure '{s}'", .{@errorName(err)}),
            .owner = b,
            .makeFn = FailStep.make,
        }),
        .msg = msg_duped,
        .err = err,
    };

    return &failure.step;
}
