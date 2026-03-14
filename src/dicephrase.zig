const std = @import("std");

pub fn generateDicePhrase(
    allocator: std.mem.Allocator,
    word_count: usize,
    words: []const []const u8,
) ![]u8 {
    if (words.len != 7776)
        return error.InvalidWordList;

    var rng = std.crypto.random;

    var selected = try std.ArrayList([]const u8).initCapacity(allocator, word_count);
    defer selected.deinit();

    for (0..word_count) |_| {
        var index: usize = 0;

        // roll 5 dice
        for (0..5) |_| {
            const roll = rng.intRangeLessThan(u8, 1, 7) - 1; // 0..5
            index = index * 6 + roll;
        }

        try selected.append(words[index]);
    }

    return std.mem.join(allocator, "-", selected.items);
}
