const std = @import("std");

const charset =
    "abcdefghijklmnopqrstuvwxyz" ++
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ++
    "0123456789";

pub fn generate(
    allocator: std.mem.Allocator,
    len: usize,
) ![]u8 {
    const out = try allocator.alloc(u8, len);

    for (out) |*c| {
        const idx = std.crypto.random.intRangeLessThan(
            usize,
            0,
            charset.len,
        );
        c.* = charset[idx];
    }

    return out;
}

test "password length" {
    const allocator = std.testing.allocator;

    const pw = try generate(allocator, 16);
    defer allocator.free(pw);

    std.debug.print("{s}\n", .{pw});
    try std.testing.expect(pw.len == 16);
}
