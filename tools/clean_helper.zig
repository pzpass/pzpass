const std = @import("std");

pub fn main() !void {
    std.fs.cwd().deleteTree("zig-out") catch |err| {
        if (err != error.FileNotFound) {
            std.debug.print("Failed to remove zig-out: {}\n", .{err});
        }
    };

    std.fs.cwd().deleteTree("tmp") catch |err| {
        if (err != error.FileNotFound) {
            std.debug.print("Failed to remove tmp: {}\n", .{err});
        }
    };

    std.debug.print("Clean completed successfully\n", .{});
}
