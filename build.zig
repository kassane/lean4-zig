const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("lean4", .{
        .source_file = .{
            .path = "src/c.zig",
        },
    });
    lean4FFI(b);
    try runTest(b, target);
    try reverseFFI(b, .{ target, optimize });
}

fn lean4FFI(b: *std.Build) void {
    const lake = b.findProgram(&.{"lake"}, &.{}) catch @panic("lake not found!");
    const lakebuild = lakeBuild(b, "examples/ffi/app");
    const update = b.addSystemCommand(&.{
        lake,
        "--dir=examples/ffi/app",
        "update",
    });
    const run = b.addSystemCommand(&.{
        "examples/ffi/app/build/bin/app",
    });
    lakebuild.step.dependOn(&update.step);
    run.step.dependOn(&lakebuild.step);
    const run_cmd = b.step("zffi", "run zig-lib on lean4-app");
    run_cmd.dependOn(&run.step);
}

fn reverseFFI(b: *std.Build, info: struct { std.zig.CrossTarget, std.builtin.OptimizeMode }) !void {
    const exe = b.addExecutable(.{
        .name = "reverse-ffi",
        .root_source_file = .{ .path = "examples/reverse-ffi/app/app.zig" },
        .target = info[0],
        .optimize = info[1],
    });
    exe.addModule("lean4", b.modules.get("lean4").?);
    exe.addLibraryPath(.{ .path = "examples/reverse-ffi/lib/build/lib" });
    const lean4_prefix = try lean4Prefix(b);
    const lib_dir = lean4LibDir(b, lean4_prefix);
    exe.addLibraryPath(.{ .path = lib_dir });

    if (exe.target.isDarwin()) {
        exe.addLibraryPath(.{ .path = "/usr/local/lib" });
    }
    exe.addIncludePath(.{ .path = b.pathJoin(&.{ lean4_prefix, "include" }) });
    exe.step.dependOn(&lakeBuild(b, "examples/reverse-ffi/lib").step);

    // static obj
    exe.addCSourceFile(.{ .file = .{ .path = "examples/reverse-ffi/lib/build/ir/RFFI.c" }, .flags = &.{} });
    if (exe.target.isWindows()) {
        exe.linkSystemLibraryName("libleanshared");
    } else {
        // exe.linkSystemLibrary("RFFI"); // sharedlib
        exe.linkSystemLibraryName("leanshared");
    }
    exe.linkLibC();

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    if (exe.target.isWindows()) run_cmd.addPathDir(lib_dir);
    const run_step = b.step("rffi", b.fmt("Run the {s} app", .{exe.name}));
    run_step.dependOn(&run_cmd.step);
}

fn lakeBuild(b: *std.Build, path: []const u8) *std.Build.Step.Run {
    const lake = b.findProgram(&.{"lake"}, &.{}) catch @panic("lake not found!");
    const run = b.addSystemCommand(&.{
        lake,
        b.fmt("--dir={s}", .{path}),
        "build",
    });
    return run;
}

fn lean4LibDir(b: *std.Build, lean4_prefix: []const u8) []const u8 {
    return if (b.target.isWindows())
        b.pathJoin(&.{ lean4_prefix, "bin" })
    else
        b.pathJoin(&.{ lean4_prefix, "lib", "lean" });
}
fn lean4Prefix(b: *std.Build) ![]const u8 {
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

fn runTest(b: *std.build, target: std.zig.CrossTarget) !void {
    const main_tests = b.addTest(.{
        .name = "lean_test",
        .target = target,
        .optimize = .Debug,
        .root_source_file = .{ .path = "src/c.zig" },
    });
    const lib_dir = lean4LibDir(b, try lean4Prefix(b));
    main_tests.addLibraryPath(.{ .path = lib_dir });

    if (main_tests.target.isDarwin()) {
        main_tests.addLibraryPath(.{ .path = "/usr/local/lib" });
    }
    if (main_tests.target.isWindows()) {
        main_tests.linkSystemLibraryName("libleanshared");
    } else {
        main_tests.linkSystemLibraryName("leanshared");
    }
    main_tests.linkLibC();
    const run_main_tests = b.addRunArtifact(main_tests);
    if (main_tests.target.isWindows()) run_main_tests.addPathDir(lib_dir);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
}
