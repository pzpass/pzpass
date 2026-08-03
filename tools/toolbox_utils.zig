const std = @import("std");

pub fn downloadFile(init: std.process.Init, allocator: std.mem.Allocator, url: []const u8, destination: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFile(init.io, destination, .{
        .truncate = true,
    });
    defer file.close(init.io);

    var file_write_buf: [4096]u8 = undefined;
    var file_writer = file.writerStreaming(init.io, &file_write_buf);

    var client = std.http.Client{ .io = init.io, .allocator = allocator };

    const uri = try std.Uri.parse(url);
    const res = client.fetch(.{
        .method = .GET,
        .location = .{ .uri = uri },
        .response_writer = &file_writer.interface,
    }) catch |err| switch (err) {
        else => std.debug.panic("Error during fetch: {}\n", .{err}),
    };
    if (res.status != .ok) {
        std.debug.print("Could not fetch {s}\n", .{destination});
    }
}
