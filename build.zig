const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("pzpass", .{
        .root_source_file = b.path("src/pzpass.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "pzp",
        .root_module = b.createModule(.{
            .root_source_file = b.path("cli/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "pzpass", .module = mod },
            },
        }),
    });

    if (optimize == .ReleaseFast) {
        mod.strip = true;
        exe.root_module.strip = true;
        b.install_path = buildLocalBinPath(b.allocator);
        const install_exe = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .prefix },
        });
        b.getInstallStep().dependOn(&install_exe.step);
    } else {
        b.installArtifact(exe);
    }

    const run_step = b.step("run", "Run the app");

    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    const dice_list_gen = b.addExecutable(.{
        .name = "dice_list_gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/dicelist_generator.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const run_dice_list_gen = b.addRunArtifact(dice_list_gen);
    run_dice_list_gen.addArg("dict/words.txt");
    const generated_dice_list_file = run_dice_list_gen.addOutputFileArg("src/dicelist.zig");

    const write_file_dice_list_gen = b.addUpdateSourceFiles();
    write_file_dice_list_gen.addCopyFileToSource(generated_dice_list_file, "src/dicelist.zig");

    const dice_list_gen_step = b.step("gen", "Generate dice list lookup");
    dice_list_gen_step.dependOn(&write_file_dice_list_gen.step);
    exe.step.dependOn(dice_list_gen_step);
}

fn createLocalBinDirectory(local_bin_path: []const u8) void {
    std.fs.cwd().makeDir(local_bin_path) catch |err| switch (err) {
        error.PathAlreadyExists => return,
        else => {
            std.debug.print("Could not create directory: {}\n", .{err});
        },
    };
}

fn buildLocalBinPath(allocator: std.mem.Allocator) []const u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch |err| {
        std.debug.panic("Could not find home directory: {}\n", .{err});
    };
    const local_bin_path = std.fs.path.join(allocator, &[_][]const u8{
        home,
        ".local/bin",
    }) catch |err| {
        std.debug.panic("Could not local bin path: {}\n", .{err});
    };
    return local_bin_path;
}
