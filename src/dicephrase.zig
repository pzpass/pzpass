const std = @import("std");
const pzcrypt = @import("crypto.zig");
const termios = @import("termios.zig");
const words = @import("dicelist.zig").dice_words;

const Allocator = std.mem.Allocator;

pub fn runPassphraseGenerator(
    allocator: Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    in: *std.Io.Reader,
    args: []const [:0]const u8,
) !void {
    const word_count = if (args.len > 2)
        std.fmt.parseInt(usize, args[2], 10) catch 5
    else
        5;
    while (true) {
        const original_termios = try std.posix.tcgetattr(std.posix.STDOUT_FILENO);
        defer termios.reset_terminal(original_termios);

        try termios.set_terminal(original_termios);

        const dicephrase = try generateDicePhrase(allocator, io, word_count);
        defer {
            pzcrypt.zeroAndMunlock(dicephrase);
            allocator.free(dicephrase);
        }
        try out.print("{s}\n", .{dicephrase});
        try out.flush();

        try in.fillMore();
        const key = try in.takeByte();
        if (key == 27 or key == 'q') { // 27 is Escape
            break;
        }
    }
}

pub fn generateDicePhrase(
    allocator: Allocator,
    io: std.Io,
    word_count: usize,
) ![]u8 {
    if (words.len < 7776)
        return error.InvalidWordList;

    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var selected = try std.ArrayList([]const u8).initCapacity(allocator, word_count);
    defer selected.deinit(allocator);

    for (0..word_count) |_| {
        var index: usize = 0;

        for (0..rng.intRangeLessThan(usize, 1, 10)) |_| {
            index = rng.intRangeLessThan(usize, 0, words.len);
        }

        try selected.append(allocator, try words.get(index));
    }

    const passphrase = try std.mem.join(allocator, "-", selected.items);
    try pzcrypt.mlockSlice(passphrase);
    return passphrase;
}

test "generated prase word count" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const dicephrase = try generateDicePhrase(allocator, io, 5);
    defer allocator.free(dicephrase);

    try std.testing.expect(dicephrase.len > 0);
}

test "get first word" {
    const word = try words.get(0);
    try std.testing.expectEqualSlices(u8, word, "aaron");
}

test "get last word" {
    const word = try words.get(words.len - 1);
    try std.testing.expectEqualSlices(u8, word, "zurich");
}

test "get out of bounds" {
    try std.testing.expectError(error.OutOfBounds, words.get(words.len));
}
