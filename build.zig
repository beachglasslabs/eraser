const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    // build options

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const clear_buckets_google_cloud = b.option(bool, "clear-buckets-google-cloud", "Confirm clearing google cloud buckets");
    const clear_buckets_aws_profile_name = b.option([]const u8, "clear-buckets-aws-profile-name", "Profile name used to clear AWS buckets");

    const shard_count = b.option(u7, "shard-count", "Erasure shard count to specify for executables and tests");
    const shards_required = b.option(u7, "shards-required", "Erasure shard size to specify for executables and tests");
    const word_size = b.option([]const u8, "word-size", "Erasure word size to specify for executables and tests");

    const difftest_file_paths: []const []const u8 = b.option([]const []const u8, "dt", "List of paths of inputs to test") orelse &.{};
    const difftest_rng_seed = b.option(u64, "dt-rng-seed", "Seed used for RNG");

    // top level steps

    const erasure_demo_step = b.step("erasure-demo", "Run the app");
    const pipeline_demo_step = b.step("pipeline-demo", "Run the library test executable");
    const unit_test_step = b.step("unit-test", "Run library tests");
    const difftest_step = b.step("diff-test", "Test for correct behaviour of the executable in encoding and decoding inputs specified via '-Ddt=[path]'");
    const clear_buckets_step = b.step("clear-buckets", "Clear all buckets of all objects (INVOKES `gcloud`, FOR TESTING PURPOSES ONLY).");

    // main modules

    const util_mod = b.createModule(.{
        .source_file = Build.LazyPath.relative("src/util.zig"),
    });
    const aws_mod = b.createModule(.{
        .source_file = Build.LazyPath.relative("src/aws.zig"),
    });
    const erasure_mod = b.addModule("erasure", .{
        .source_file = Build.LazyPath.relative("src/erasure.zig"),
        .dependencies = &.{
            .{ .name = "util", .module = util_mod },
            .{ .name = "aws", .module = aws_mod },
        },
    });
    const pipelines_mod = b.addModule("eraser", .{
        .source_file = Build.LazyPath.relative("src/pipelines.zig"),
        .dependencies = &.{
            .{ .name = "util", .module = util_mod },
        },
    });

    // everything else

    const erasure_demo_exe = b.addExecutable(.{
        .name = "erasure-demo",
        .root_source_file = Build.LazyPath.relative("tests/erasure-demo.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(erasure_demo_exe);
    erasure_demo_exe.addModule("erasure", erasure_mod);

    const erasure_demo_run = b.addRunArtifact(erasure_demo_exe);
    erasure_demo_step.dependOn(&erasure_demo_run.step);
    erasure_demo_run.step.dependOn(b.getInstallStep());
    erasure_demo_run.stdio = .inherit;
    if (b.args) |args| erasure_demo_run.addArgs(args);

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
    pipeline_demo_run.step.dependOn(b.getInstallStep());
    pipeline_demo_run.stdio = .inherit;

    const unit_test_exe = b.addTest(.{
        .root_source_file = Build.LazyPath.relative("src/pipelines.zig"),
        .target = target,
        .optimize = optimize,
    });
    const unit_tests_run = b.addRunArtifact(unit_test_exe);
    unit_test_step.dependOn(&unit_tests_run.step);
    unit_test_exe.addModule("util", util_mod);

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

    const clear_buckets_exe = b.addExecutable(.{
        .name = "clear-buckets",
        .root_source_file = Build.LazyPath.relative("scripts/clear-buckets.zig"),
        .optimize = optimize,
    });
    const clear_buckets_run = b.addRunArtifact(clear_buckets_exe);
    clear_buckets_step.dependOn(&clear_buckets_run.step);
    if (clear_buckets_google_cloud orelse false) {
        clear_buckets_run.setEnvironmentVariable("ZIG_GOOGLE_CLOUD", "");
    }
    if (clear_buckets_aws_profile_name) |profile_name| {
        clear_buckets_run.setEnvironmentVariable("ZIG_AWS_PROFILE_NAME", profile_name);
    }
}

const WriteCompileFlags = struct {
    step: Build.Step,
    options: Options,

    pub const id: Build.Step.Id = .custom;

    const Options = struct {
        aws_include_dir: Build.LazyPath,
    };
    fn create(b: *Build, options: Options) *WriteCompileFlags {
        const self = b.allocator.create(WriteCompileFlags) catch |e| @panic(@errorName(e));
        self.* = .{
            .step = Build.Step.init(.{
                .id = WriteCompileFlags.id,
                .name = "Write compile_flags.txt",
                .owner = b,
                .makeFn = WriteCompileFlags.make,
            }),
            .options = .{
                .aws_include_dir = options.aws_include_dir.dupe(b),
            },
        };
        self.options.aws_include_dir.addStepDependencies(&self.step);
        return self;
    }

    fn make(step: *Build.Step, prog: *std.Progress.Node) anyerror!void {
        _ = prog;
        const wcf = @fieldParentPtr(WriteCompileFlags, "step", step);

        const compile_flags = try step.owner.build_root.handle.createFile("compile_flags.txt", .{});
        defer compile_flags.close();

        var buffered = std.io.bufferedWriter(compile_flags.writer());
        try buffered.writer().print(
            \\-I{s}
            \\
        , .{
            wcf.options.aws_include_dir.getPath2(step.owner, step),
        });
        try buffered.flush();
    }
};
