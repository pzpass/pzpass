const std = @import("std");
const words = @import("dicelist.zig").dice_words;

pub fn generateDicePhrase(
    allocator: std.mem.Allocator,
    word_count: usize,
) ![]u8 {
    if (words.len < 7776)
        return error.InvalidWordList;

    var rng = std.crypto.random;

    var selected = try std.ArrayList([]const u8).initCapacity(allocator, word_count);
    defer selected.deinit(allocator);

    for (0..word_count) |_| {
        var index: usize = 0;

        for (0..rng.intRangeLessThan(usize, 1, 10)) |_| {
            index = rng.intRangeLessThan(usize, 0, words.len);
        }

        try selected.append(allocator, try words.get(index));
    }

    return std.mem.join(allocator, "-", selected.items);
}

test "generated prase word count" {
    const allocator = std.testing.allocator;

    const dicephrase = try generateDicePhrase(allocator, 5);
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
