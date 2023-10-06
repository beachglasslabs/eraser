const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    // build options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const difftest_file_paths: []const []const u8 = b.option([]const []const u8, "dt", "List of paths of inputs to test") orelse &.{};

    const shard_count = b.option(u7, "shard-count", "Erasure shard count to specify for executables and tests");
    const shards_required = b.option(u7, "shards-required", "Erasure shard size to specify for executables and tests");
    const word_size = b.option([]const u8, "word-size", "Erasure word size to specify for executables and tests");
    const confirm_clear_buckets = b.option(bool, "clear-buckets", "Confirm clearing all buckets of all objects (FOR TESTING PURPOSES ONLY).");
    const difftest_rng_seed = b.option(u64, "dt-rng-seed", "Seed used for RNG");

    // top level steps
    const erasure_demo_step = b.step("erasure-demo", "Run the app");
    const pipeline_demo_step = b.step("pipeline-demo", "Run the library test executable");
    const unit_test_step = b.step("unit-test", "Run library tests");
    const difftest_step = b.step("diff-test", "Test for correct behaviour of the executable in encoding and decoding inputs specified via '-Ddt=[path]'");
    const clear_buckets_step = b.step("clear-buckets", "Clear all buckets of all objects (INVOKES `gcloud`, FOR TESTING PURPOSES ONLY).");

    // everything else

    const erasure_mod = b.addModule("erasure", .{
        .source_file = Build.LazyPath.relative("src/erasure.zig"),
    });
    const pipelines_mod = b.addModule("eraser", .{
        .source_file = Build.LazyPath.relative("src/pipelines.zig"),
    });

    const erasure_demo_exe = b.addExecutable(.{
        .name = "erasure-demo",
        .root_source_file = Build.LazyPath.relative("tests/erasure-demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(erasure_demo_exe);
    erasure_demo_exe.addModule("erasure", erasure_mod);

    const erasure_demo_run = b.addRunArtifact(erasure_demo_exe);
    erasure_demo_run.has_side_effects = true; // tell zig we want to run this every time
    erasure_demo_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| erasure_demo_run.addArgs(args);
    erasure_demo_step.dependOn(&erasure_demo_run.step);

    const pipeline_demo_exe = b.addExecutable(.{
        .name = "pipelines-demo",
        .root_source_file = Build.LazyPath.relative("tests/pipelines-demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(pipeline_demo_exe);
    pipeline_demo_exe.addModule("eraser", pipelines_mod);

    const pipeline_demo_run = b.addRunArtifact(pipeline_demo_exe);
    pipeline_demo_step.dependOn(&pipeline_demo_run.step);
    pipeline_demo_run.stdio = .inherit;

    if (b.option([]const u8, "gc-auth-key", "Google cloud auth key")) |auth_key| {
        pipeline_demo_run.setEnvironmentVariable("ZIG_TEST_GOOGLE_CLOUD_AUTH_KEY", auth_key);
    }

    const unit_test_exe = b.addTest(.{
        .root_source_file = Build.LazyPath.relative("src/pipelines.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests_run = b.addRunArtifact(unit_test_exe);
    unit_test_step.dependOn(&unit_tests_run.step);

    const difftest_exe = b.addTest(.{
        .name = "diff-test",
        .root_source_file = Build.LazyPath.relative("tests/difftest.zig"),
        .target = target,
        .optimize = optimize,
    });
    const difftest_build_options = b.addOptions();
    difftest_exe.addOptions("build-options", difftest_build_options);
    difftest_build_options.addOption([]const []const u8, "inputs", difftest_file_paths);
    difftest_build_options.addOption(u7, "shard_count", shard_count orelse 6);
    difftest_build_options.addOption(u7, "shards_required", shards_required orelse 3);
    difftest_build_options.addOption(u64, "seed", difftest_rng_seed orelse 0xdeadbeef);
    difftest_build_options.contents.writer().print("pub const Word: type = {};\n", .{std.zig.fmtId(word_size orelse "u8")}) catch |err| @panic(@errorName(err));

    difftest_exe.addModule("erasure", erasure_mod);
    const difftest_run = b.addRunArtifact(difftest_exe);
    difftest_step.dependOn(&difftest_run.step);

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
