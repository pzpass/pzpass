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

    try writer_interface.writeAll(
        \\const std = @import("std");
        \\const expect = std.testing.expect;
        \\const expectEqualSlices = std.testing.expectEqualSlices;
        \\
        \\const words_blob = "
    );

    var word_length = try std.ArrayList(usize).initCapacity(allocator, 20_000);
    defer word_length.deinit(allocator);

    while (try read_file_interface.takeDelimiter('\n')) |line| {
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        var parts = std.mem.tokenizeScalar(u8, line, ' ');

        while (parts.next()) |p| {
            const trimmed = std.mem.trim(u8, p, " \t");
            if (trimmed.len == 0) continue;
            try writer_interface.print("{s}", .{p});
            try word_length.append(allocator, p.len);
        }
    }
    try writer_interface.writeAll("\";\n");
    try writer_interface.writeAll("const offsets = [_]usize{0");
    var offset_accum: usize = 0;

    for (word_length.items) |item| {
        offset_accum += item;
        try writer_interface.print(", {d}", .{offset_accum});
    }
    try writer_interface.writeAll("};");
    try writer_interface.writeAll(
        \\
        \\pub const DiceWords = struct {
        \\    words_blob: []const u8,
        \\    words_offsets: []const usize,
        \\    len: usize,
        \\
        \\    pub fn get(self: @This(), index: usize) ![]const u8 {
        \\        return self.words_blob[self.words_offsets[index]..self.words_offsets[index + 1]];
        \\    }
        \\};
        \\
        \\pub const dice_words = DiceWords{
        \\    .words_blob = words_blob,
        \\    .words_offsets = &offsets,
    );
    try writer_interface.print(
        \\    .len = {d},
    , .{word_length.items.len - 1});
    try writer_interface.writeAll(
        \\};
        \\
        \\test "dice word length" {
        \\    try std.testing.expect(dice_words.len > 7775);
        \\}
        \\
        \\test "dice word lookup 0" {
        \\    try std.testing.expect((try dice_words.get(0)).len != 0);
        \\}
        \\
        \\test "dice word lookup 7776" {
        \\    try std.testing.expect((try dice_words.get(7776)).len != 0);
        \\}
        \\
        \\test "dice word lookup end" {
        \\    try std.testing.expect((try dice_words.get(dice_words.len)).len != 0);
        \\}
        \\
        \\test "get first word" {
        \\    const word = try dice_words.get(0);
        \\    try std.testing.expectEqualSlices(u8, word, "aaron");
        \\}
        \\
        \\test "get last word" {
        \\    const word = try dice_words.get(dice_words.len);
        \\    try std.testing.expectEqualSlices(u8, word, "zurich");
        \\}
        \\
    );
    try writer_interface.flush();
}

fn getWordList(allocator: std.mem.Allocator, destination: []const u8) !void {
    try tools.downloadFile(allocator, "https://github.com/pzpass/pzpass/blob/v0.0.0/dict/words.txt", destination);
}
