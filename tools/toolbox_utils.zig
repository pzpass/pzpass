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

fn printFileLineByLineExceptCommentsAndEmptyLines(file_path: []const u8) !void {
    const read_file = try std.Io.Dir.cwd().openFile(file_path, .{ .mode = .read_only });
    defer read_file.close();

    var read_buff: [4096]u8 = undefined;
    var read_file_reader = read_file.reader(&read_buff);
    const read_file_interface = &read_file_reader.interface;

    while (try read_file_interface.takeDelimiter('\n')) |line_raw| {
        const line = std.mem.trim(u8, line_raw, "\r");
        if (line.len == 0) continue;
        if (line[0] == '#') continue;
        std.debug.print("{s}\n", .{line});
    }
}
