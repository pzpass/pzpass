const std = @import("std");
const pzcrypt = @import("crypto.zig");

const alignment = std.mem.Alignment.fromByteUnits(std.heap.page_size_min);
const charset =
    "abcdefghijklmnopqrstuvwxyz" ++
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" ++
    "0123456789" ++
    "!@#$%^&*()-_=+[]{}|;:,.<>?";

pub fn runPasswordGenerator(
    allocator: std.mem.Allocator,
    io: std.Io,
    out: *std.Io.Writer,
    args: []const [:0]const u8,
) !void {
    const password_length = if (args.len > 2)
        std.fmt.parseInt(usize, args[2], 10) catch 20
    else
        20;
    const pw = try generate(allocator, io, password_length);
    defer {
        pzcrypt.zeroAndMunlock(pw);
        allocator.free(pw);
    }
    try out.print("{s}\n", .{pw});
}

pub fn generate(
    allocator: std.mem.Allocator,
    io: std.Io,
    len: usize,
) ![]u8 {
    const out = try allocator.alignedAlloc(u8, alignment, len);
    try pzcrypt.mlockSlice(out);

    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    for (out) |*c| {
        const idx = rng.intRangeLessThan(
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
    const io = std.testing.io;

    const pw = try generate(allocator, io, 16);
    defer allocator.rawFree(pw, alignment, std.heap.page_size_min);

    try std.testing.expect(pw.len == 16);
}
