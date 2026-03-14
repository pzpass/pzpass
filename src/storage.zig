const std = @import("std");

pub fn defaultVaultPath(allocator: std.mem.Allocator) ![]u8 {
    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);

    return std.fmt.allocPrint(
        allocator,
        "{s}/.pzpass/vault.dat",
        .{home},
    );
}

test "default path" {
    const allocator = std.testing.allocator;

    const default_path = try defaultVaultPath(allocator);
    defer allocator.free(default_path);

    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);

    const expected = try std.fmt.allocPrint(
        allocator,
        "{s}/.pzpass/vault.dat",
        .{home},
    );
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, default_path);
}
