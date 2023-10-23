const std = @import("std");
const Build = std.Build;

const zas3 = @import("zig-aws-s3");

pub fn build(b: *Build) void {
    // build options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const confirm_clear_buckets = b.option(bool, "clear-buckets", "Confirm clearing all buckets of all objects (FOR TESTING PURPOSES ONLY).");

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
    const lsp_install_step = b.step("lsp-install", "Install generated files for LSPs to more easily find");

    // dependencies
    const zig_aws_s3_dep = b.dependency("zig-aws-s3", .{
        .target = target,
        .optimize = optimize,
        .cmake_exe = b.option([]const u8, "cmake_exe", "CMake executable path") orelse "cmake",
    });

    // main modules
    const erasure_mod = b.addModule("erasure", .{
        .source_file = Build.LazyPath.relative("src/erasure.zig"),
    });
    const pipelines_mod = b.addModule("eraser", .{
        .source_file = Build.LazyPath.relative("src/pipelines.zig"),
    });

    const aws_include_dir: Build.LazyPath = blk: {
        const cached = zas3.awsIncludeDir(zig_aws_s3_dep);
        const called_from_zls = b.option(bool, "called-from-zls", "This flag should be passed by ZLS") orelse false;

        // this helps the C LSP
        const wcf = WriteCompileFlags.create(b, .{
            .aws_include_dir = cached,
        });
        lsp_install_step.dependOn(&wcf.step);

        // this is done here to help ZLS do autocompletion
        const install_dir = b.addInstallDirectory(.{
            .source_dir = cached,
            .install_dir = .{ .custom = "lsp" },
            .install_subdir = "aws-include",
        });
        lsp_install_step.dependOn(&install_dir.step);

        if (!called_from_zls) break :blk cached; // use cached path if this is just a normal build invokation
        break :blk .{ .path = b.getInstallPath(install_dir.options.install_dir, install_dir.options.install_subdir) };
    };

    // everything else

    const zaws_include_dir: Build.LazyPath = .{ .path = "src" };
    const zaws_obj_file = b.addObject(.{
        .name = "zaws",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    zaws_obj_file.addIncludePath(aws_include_dir);
    zaws_obj_file.addIncludePath(zaws_include_dir);
    zaws_obj_file.addCSourceFiles(.{
        .flags = &.{},
        .files = &.{
            "src/zaws/aws_signing_config_aws.c",
            "src/zaws/aws_s3_client_new.c",
        },
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
    pipeline_demo_exe.linkLibC();

    zas3.linkAwsLibs(pipeline_demo_exe, zig_aws_s3_dep);
    pipeline_demo_exe.addIncludePath(aws_include_dir);

    pipeline_demo_exe.addIncludePath(zaws_include_dir);
    pipeline_demo_exe.addObject(zaws_obj_file);

    const pipeline_demo_run = b.addRunArtifact(pipeline_demo_exe);
    pipeline_demo_step.dependOn(&pipeline_demo_run.step);
    pipeline_demo_run.step.dependOn(b.getInstallStep());
    pipeline_demo_run.stdio = .inherit;

    if (b.option([]const u8, "gc-auth-tok", "Google cloud auth token")) |auth_tok| {
        pipeline_demo_run.addArg(auth_tok);
    }
    blk: {
        const maybe_aws_auth = b.option([]const u8, "aws-auth", "AWS auth token");
        const maybe_aws_auth_sec = b.option([]const u8, "aws-auth-sec", "AWS auth token");

        const aws_auth = maybe_aws_auth orelse break :blk;
        const aws_auth_sec = maybe_aws_auth_sec orelse break :blk;

        pipeline_demo_run.addArg(aws_auth);
        pipeline_demo_run.addArg(aws_auth_sec);
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
