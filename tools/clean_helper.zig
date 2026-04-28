const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const dir_list = [_][]const u8{
        "zig-out",
        "tmp",
        ".pzpass",
    };

    for (dir_list) |item| {
        std.Io.Dir.cwd().deleteTree(init.io, item) catch |err| {
            if (err != error.FileNotFound) {
                std.debug.print("Failed to remove {s}: {}\n", .{ item, err });
            }
        };
    }

    std.debug.print("Clean completed successfully\n", .{});
}
