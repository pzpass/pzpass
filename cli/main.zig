const std = @import("std");
const pzpass = @import("pzpass");

pub fn main(init: std.process.Init) !void {
    try pzpass.run(init);
}

test "dummy test" {
    try std.testing.expect(true);
}
