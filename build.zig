const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    // build options
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // top level steps
    const run_step = b.step("run", "Run the app");
    const unit_test_step = b.step("unit-test", "Run library tests");
    const difftest_step = b.step("diff-test", "Run the binary on a test case");

    const lib = b.addStaticLibrary(.{
        .name = "eraser",
        .root_source_file = Build.LazyPath.relative("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "eraser",
        .root_source_file = Build.LazyPath.relative("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    run_exe.has_side_effects = true; // tell zig we want to run this every time
    run_exe.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_exe.addArgs(args);
    run_step.dependOn(&run_exe.step);

    const main_tests = b.addTest(.{
        .root_source_file = Build.LazyPath.relative("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_main_tests = b.addRunArtifact(main_tests);
    unit_test_step.dependOn(&run_main_tests.step);

    for (b.option([]const []const u8, "diff-test", "Which inputs to test") orelse &.{}) |file_name| {
        const input = Build.LazyPath.relative(b.pathJoin(&.{ "tests/inputs", file_name }));
        const output = encodeAndDecode(b, exe, input);

        const difftest_exe = b.addTest(.{
            .name = "difftest",
            .root_source_file = Build.LazyPath.relative("tests/difftest.zig"),
            .target = target,
            .optimize = optimize,
        });
        const paths = b.addOptions();
        difftest_exe.addOptions("paths", paths);
        paths.addOptionPath("input", input);
        paths.addOptionPath("output", output);

        const run_difftest_exe = b.addRunArtifact(difftest_exe);
        run_difftest_exe.has_side_effects = true;

        difftest_step.dependOn(&run_difftest_exe.step);
    }
}

fn encodeAndDecode(
    b: *Build,
    eraser_artifact: *Build.CompileStep,
    input: Build.LazyPath,
) Build.LazyPath {
    // encode
    const run_exe_difftest_encode = b.addRunArtifact(eraser_artifact);
    run_exe_difftest_encode.addArg("encode");

    run_exe_difftest_encode.addArg("--data");
    run_exe_difftest_encode.addFileArg(input);

    run_exe_difftest_encode.addArg("--code");
    const difftest_output_dir = run_exe_difftest_encode.addOutputFileArg("output");

    // decode
    const run_exe_difftest_decode = b.addRunArtifact(eraser_artifact);
    run_exe_difftest_decode.addArg("decode");

    run_exe_difftest_decode.addArg("--data");
    const output = run_exe_difftest_decode.addOutputFileArg("output.txt");

    run_exe_difftest_decode.addArg("--code");
    run_exe_difftest_decode.addDirectoryArg(difftest_output_dir);

    return output;
}
