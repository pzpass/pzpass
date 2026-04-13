const std = @import("std");
const pzpass = @import("pzpass");

pub fn main() !void {
    try pzpass.run();
}

test "dummy test" {
    try std.testing.expect(true);
}
