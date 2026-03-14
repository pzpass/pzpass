const std = @import("std");
const pzpass = @import("pzpass");

pub fn main() !void {
    try pzpass.bufferedPrint();
}

test "dummy" {
    try std.testing.expect(true);
}
