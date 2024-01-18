const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "zffi",
        .root_source_file = .{ .path = "zig/ffi.zig" },
        .target = target,
        .optimize = optimize,
    });
    lib.pie = true;
    lib.root_module.addAnonymousImport("lean4", .{
        .root_source_file = .{
            .path = "../../../src/c.zig",
        },
    });
    switch (optimize) {
        .Debug, .ReleaseSafe => lib.bundle_compiler_rt = true,
        else => lib.root_module.strip = true,
    }
    const libname = switch (lib.rootModuleTarget().abi) {
        .msvc => b.fmt("{s}.lib", .{lib.name}),
        else => if (lib.rootModuleTarget().isMinGW())
            b.fmt("{s}.a", .{lib.name})
        else
            b.fmt("lib{s}.a", .{lib.name}),
    };
    const lib_install = b.addInstallFileWithDir(lib.getEmittedBin(), .lib, libname);
    lib_install.step.dependOn(&lib.step);
    b.getInstallStep().dependOn(&lib_install.step);
}
