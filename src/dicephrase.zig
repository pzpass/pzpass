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
        defer termios.reset_terminal(original_termios) catch {};

        try termios.set_terminal(original_termios);

        const dicephrase = try generateDicePhrase(allocator, io, word_count);
        defer pzcrypt.freeSecret(allocator, dicephrase);
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
) !pzcrypt.Secret {
    if (words.len < 7776)
        return error.InvalidWordList;

    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    var longest: usize = 0;
    for (0..words.len) |i| longest = @max(longest, (try words.get(i)).len);

    // Build the phrase in a locked buffer big enough for any choice of words,
    // then copy it to an exact-size one. (The previous version kept the chosen
    // words in an unlocked list and joined them in unlocked memory.)
    const capacity = try std.math.mul(usize, word_count, longest + 1);
    const scratch = try pzcrypt.allocSecret(allocator, capacity);
    defer pzcrypt.freeSecret(allocator, scratch);

    var len: usize = 0;
    for (0..word_count) |i| {
        if (i != 0) {
            scratch[len] = '-';
            len += 1;
        }
        const word = try words.get(rng.intRangeLessThan(usize, 0, words.len));
        @memcpy(scratch[len..][0..word.len], word);
        len += word.len;
    }

    return pzcrypt.dupeSecret(allocator, scratch[0..len]);
}

test "generated prase word count" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const dicephrase = try generateDicePhrase(allocator, io, 5);
    defer pzcrypt.freeSecret(allocator, dicephrase);

    try std.testing.expect(dicephrase.len > 0);
    try std.testing.expectEqual(@as(usize, 5), std.mem.count(u8, dicephrase, "-") + 1);
    var it = std.mem.splitScalar(u8, dicephrase, '-');
    while (it.next()) |word| try std.testing.expect(word.len > 0);
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
