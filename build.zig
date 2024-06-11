const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    const libusb = b.dependency("libusb", .{
        .optimize = optimize,
        .target = target,
    });

    const adb = b.addModule("adb", .{
        .root_source_file = b.path("src/root.zig"),
        .optimize = optimize,
        .target = target,
    });

    adb.linkSystemLibrary("openssl", .{});
    adb.addImport("libusb", libusb.module("libusb"));

    const example_screencap = b.addExecutable(.{
        .name = "example_screencap",
        .root_source_file = b.path("src/examples/screencap.zig"),
        .target = target,
        .optimize = optimize,
    });

    example_screencap.root_module.addImport("adb", adb);

    b.installArtifact(example_screencap);

    const run_example_screencap_cmd = b.addRunArtifact(example_screencap);
    run_example_screencap_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_example_screencap_cmd.addArgs(args);
    }

    const run_example_screencap_step = b.step("run_example_screencap", "Run the app");
    run_example_screencap_step.dependOn(&run_example_screencap_cmd.step);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    lib_unit_tests.linkSystemLibrary("openssl");
    lib_unit_tests.root_module.addImport("libusb", libusb.module("libusb"));

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(lib_unit_tests).step);
}
