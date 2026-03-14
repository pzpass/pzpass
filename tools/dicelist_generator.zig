const std = @import("std");
const tools = @import("toolbox_utils.zig");

const debug = false;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(allocator);
    if (args.len < 3) std.debug.panic("wrong number of arguments", .{});

    const conf_file = args[1];
    const output_file = args[2];

    std.fs.cwd().access(conf_file, .{}) catch |err| switch (err) {
        error.FileNotFound => try getWordList(allocator, conf_file),
        else => {
            std.debug.print("{}\n", .{err});
        },
    };

    const read_file = try std.fs.cwd().openFile(conf_file, .{});
    defer read_file.close();

    var read_buff: [4096]u8 = undefined;
    var read_file_reader = read_file.reader(&read_buff);
    const read_file_interface = &read_file_reader.interface;

    var file = try std.fs.cwd().createFile(output_file, .{
        .truncate = true,
    });
    defer file.close();

    var file_write_buf: [4096]u8 = undefined;
    var writer = file.writerStreaming(&file_write_buf);
    const writer_interface = &writer.interface;

    // try writer_interface.print("pub const table: [_]u21 = .{{\n", .{});
    try writer_interface.writeAll(
        \\const std = @import("std");
        \\const expect = std.testing.expect;
        \\const expectEqualSlices = std.testing.expectEqualSlices;
        \\
        \\const dice_words = [_][]const u8{
        \\
    );

    while (try read_file_interface.takeDelimiter('\n')) |line| {
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        var parts = std.mem.splitScalar(u8, line, ' ');

        while (parts.next()) |p| {
            const trimmed = std.mem.trim(u8, p, " \t");
            if (trimmed.len == 0) continue;
            try writer_interface.print("\"{s}\",\n", .{p});
        }
    }

    try writer_interface.writeAll(
        \\};
        \\
        \\test "dice word length" {
        \\    try std.testing.expect(dice_words.len > 7775);
        \\}
        \\
        \\test "dice word lookup" {
        \\    try std.testing.expect(dice_words[0].len != 0);
        \\    try std.testing.expect(dice_words[7776].len != 0);
        \\}
        \\
    );
    try writer_interface.flush();
}

fn getWordList(allocator: std.mem.Allocator, destination: []const u8) !void {
    try tools.downloadFile(allocator, "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt", destination);
}

// https://www.desiquintans.com/downloads/nounlist/nounlist.txt
// https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
