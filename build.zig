const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const shared = b.option(bool, "Shared", "Linking with libleanshared [default: true]") orelse true;

    _ = b.addModule("lean4", .{
        .root_source_file = .{
            .path = "src/c.zig",
        },
    });
    lean4FFI(b);
    try runTest(b, target);
    try reverseFFI(b, .{
        .target = target,
        .optimize = optimize,
        .linkage = switch (shared) {
            true => .dynamic,
            false => .static,
        },
    });
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
        "examples/ffi/app/.lake/build/bin/app",
    });
    lakebuild.step.dependOn(&update.step);
    run.step.dependOn(&lakebuild.step);
    const run_cmd = b.step("zffi", "run zig-lib on lean4-app");
    run_cmd.dependOn(&run.step);
}

fn reverseFFI(b: *std.Build, info: BuildInfo) !void {
    const exe = b.addExecutable(.{
        .name = "reverse-ffi",
        .root_source_file = .{ .path = "examples/reverse-ffi/app/app.zig" },
        .target = info.target,
        .optimize = info.optimize,
    });
    exe.root_module.addImport("lean4", b.modules.get("lean4").?);
    exe.addLibraryPath(.{ .path = "examples/reverse-ffi/lib/build/lib" });
    const lean4_prefix = try lean4Prefix(b);
    const lib_dir = lean4LibDir(b, lean4_prefix);
    exe.addLibraryPath(.{ .path = lib_dir });

    if (exe.rootModuleTarget().isDarwin()) {
        exe.addLibraryPath(.{ .path = "/usr/local/lib" });
    }
    exe.addIncludePath(.{ .path = b.pathJoin(&.{ lean4_prefix, "include" }) });
    exe.step.dependOn(&lakeBuild(b, "examples/reverse-ffi/lib").step);

    // static obj
    exe.addCSourceFile(.{ .file = .{ .path = "examples/reverse-ffi/lib/.lake/build/ir/RFFI.c" }, .flags = &.{} });

    if (exe.rootModuleTarget().os.tag == .linux and info.linkage == .static) {
        exe.linkSystemLibrary("leancpp");
        exe.linkSystemLibrary("leanrt");
        exe.linkSystemLibrary("Init");
        exe.linkSystemLibrary("Lean");
        exe.linkSystemLibrary("gmp");
        exe.linkLibCpp(); // libc++ + libunwind + libc
    } else {
        if (exe.rootModuleTarget().os.tag == .windows) {
            // search library name - no pkg-config
            exe.linkSystemLibrary2("leanshared.dll", .{ .use_pkg_config = .no });
        } else {
            // detect library w/ pkg-config
            exe.linkSystemLibrary("leanshared");
        }
        exe.linkLibC();
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    if (exe.rootModuleTarget().os.tag == .windows)
        run_cmd.addPathDir(lib_dir);
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
    // for windows/mingw need "lib.dll.a" linking
    return b.pathJoin(&.{ lean4_prefix, "lib", "lean" });
}
fn lean4Prefix(b: *std.Build) ![]const u8 {
    const lean = try b.findProgram(&.{"lean"}, &.{});
    const run = try std.ChildProcess.run(.{
        .allocator = b.allocator,
        .argv = &.{
            lean,
            "--print-prefix",
        },
    });
    var out = std.mem.splitSequence(u8, run.stdout, "\n"); // remove newline
    return out.first();
}

fn runTest(b: *std.Build, target: std.Build.ResolvedTarget) !void {
    const libTests = b.addTest(.{
        .name = "lean_test",
        .target = target,
        .optimize = .Debug,
        .root_source_file = .{ .path = "src/c.zig" },
    });
    const lib_dir = lean4LibDir(b, try lean4Prefix(b));
    libTests.addLibraryPath(.{ .path = lib_dir });

    if (libTests.rootModuleTarget().isDarwin()) {
        libTests.addLibraryPath(.{ .path = "/usr/local/lib" });
    }
    if (libTests.rootModuleTarget().os.tag == .windows) {
        libTests.linkSystemLibrary2("leanshared.dll", .{ .use_pkg_config = .no });
    } else {
        libTests.linkSystemLibrary("leanshared");
    }
    libTests.linkLibC();
    const run_libTests = b.addRunArtifact(libTests);
    if (libTests.rootModuleTarget().os.tag == .windows)
        run_libTests.addPathDir(lib_dir);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_libTests.step);
}

const BuildInfo = struct {
    linkage: std.Build.Step.Compile.Linkage,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
};
