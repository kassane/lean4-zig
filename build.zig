const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "zig_lean4",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.addLibraryPath(.{ .path = "vendor/reverse-ffi/out" });
    exe.linkSystemLibrary("RFFI");
    exe.linkSystemLibrary("leanshared");
    exe.linkLibC();
    exe.step.dependOn(&buildlib(b).step);

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", b.fmt("Run the {s} app", .{exe.name}));
    run_step.dependOn(&run_cmd.step);
}

fn buildlib(b: *std.Build) *std.Build.Step.Run {
    const run = b.addSystemCommand(&.{
        "lake",
        "--dir=vendor/reverse-ffi/lib",
        "build",
    });
    return run;
}
