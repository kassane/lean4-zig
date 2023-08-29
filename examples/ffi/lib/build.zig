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
    lib.addAnonymousModule("lean4", .{ .source_file = .{ .path = "../../../src/lean.zig" } });
    switch (optimize) {
        .Debug, .ReleaseSafe => lib.bundle_compiler_rt = true,
        else => lib.strip = true,
    }
    b.installArtifact(lib);
}
