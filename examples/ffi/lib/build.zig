const std = @import("std");

pub fn build(b: *std.build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "zffi",
        .root_source_file = .{ .path = "zig/ffi.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.pie = true;
    lib.addAnonymousModule("lean4", .{ .source_file = .{ .path = "../../../src/lean.zig" } });
    switch (optimize) {
        .Debug, .ReleaseSafe => lib.bundle_compiler_rt = true,
        else => lib.strip = true,
    }
    const libname = switch (target.getAbi()) {
        .msvc => b.fmt("{s}.lib", .{lib.name}),
        else => if (isMinGW(target)) b.fmt("{s}.a", .{lib.name}) else b.fmt("lib{s}.a", .{lib.name}),
    };
    const lib_install = b.addInstallFileWithDir(lib.getOutputSource(), .lib, libname);
    lib_install.step.dependOn(&lib.step);
    b.getInstallStep().dependOn(&lib_install.step);
}

fn isMinGW(getTarget: std.zig.CrossTarget) bool {
    const target = (std.zig.system.NativeTargetInfo.detect(getTarget) catch unreachable).target;
    return if (target.isMinGW()) true else false;
}
