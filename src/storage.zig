const std = @import("std");

pub const VaultPath = struct {
    vault_dir: []const u8,
    filename: []const u8,

    pub fn default(allocator: std.mem.Allocator, filename: ?[]const u8) ![]u8 {
        const home = try std.process.getEnvVarOwned(allocator, "HOME");
        defer allocator.free(home);

        const actual_filename = filename orelse "vault.dat";
        return std.fmt.allocPrint(
            allocator,
            "{s}/.pzpass/{s}",
            .{
                home,
                actual_filename,
            },
        );
    }
};

pub fn readFileAlloc(
    allocator: std.mem.Allocator,
    path: []const u8,
) ![]u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    return try file.readToEndAlloc(allocator, 1 << 20);
}

pub fn writeFile(
    path: []const u8,
    data: []const u8,
) !void {
    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();

    try file.writeAll(data);
}

test "default path" {
    const allocator = std.testing.allocator;

    const default_path = try VaultPath.default(allocator, null);
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
