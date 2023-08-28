const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "lean4-zig",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    exe.addLibraryPath(.{ .path = "vendor/reverse-ffi/lib/build/lib" });
    exe.addLibraryPath(.{
        .path = b.pathJoin(
            &.{
                try lean4prefix(b),
                "lib/lean",
            },
        ),
    });
    exe.step.dependOn(&lakeBuild(b).step);
    exe.linkSystemLibrary("RFFI");
    exe.linkSystemLibrary("leanshared");
    exe.linkLibC();

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", b.fmt("Run the {s} app", .{exe.name}));
    run_step.dependOn(&run_cmd.step);
}

fn lakeBuild(b: *std.Build) *std.Build.Step.Run {
    const lake = b.findProgram(&.{"lake"}, &.{}) catch @panic("lake not found!");
    const run = b.addSystemCommand(&.{
        lake,
        "--dir=vendor/reverse-ffi/lib",
        "build",
    });
    return run;
}
fn lean4prefix(b: *std.Build) ![]const u8 {
    const lean = try b.findProgram(&.{"lean"}, &.{});
    const run = try std.ChildProcess.exec(.{
        .allocator = b.allocator,
        .argv = &.{
            lean,
            "--print-prefix",
        },
    });
    var out = std.mem.split(u8, run.stdout, "\n"); // remove newline
    return out.first();
}
