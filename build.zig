const std = @import("std");
const Build = std.Build;

pub fn build(b: *Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // top level steps
    const run_step = b.step("run", "Run the app");
    const test_step = b.step("test", "Run library tests");

    const lib = b.addStaticLibrary(.{
        .name = "eraser",
        .root_source_file = Build.FileSource.relative("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    const exe = b.addExecutable(.{
        .name = "eraser",
        .root_source_file = Build.FileSource.relative("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    run_exe.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_exe.addArgs(args);
    run_step.dependOn(&run_exe.step);

    const main_tests = b.addTest(.{
        .root_source_file = Build.FileSource.relative("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_main_tests = b.addRunArtifact(main_tests);
    test_step.dependOn(&run_main_tests.step);
}
