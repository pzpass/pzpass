const std = @import("std");
const Entry = @import("entry.zig").Entry;
const storage = @import("storage.zig");

const VaultHeader = packed struct {
    magic: [6]u8,
    version: u16,
    mem_cost: u32,
    time_cost: u32,
    lanes: u32,
    salt: [16]u8,
    entry_count: u32,
};

pub const Vault = struct {
    entries: std.ArrayList(Entry),
};

pub fn initVault(allocator: std.mem.Allocator) !void {
    const path = try storage.defaultVaultPath(allocator);
    defer allocator.free(path);

    const home = try std.process.getEnvVarOwned(allocator, "HOME");
    defer allocator.free(home);

    var home_dir = try std.fs.openDirAbsolute(home, .{ .access_sub_paths = true });
    defer home_dir.close();

    home_dir.makeDir(".pzpass") catch |err| switch (err) {
        error.PathAlreadyExists => return,
        else => {
            std.debug.print("Cannot create .pzpass config directory: {}\n", .{err});
            return err;
        },
    };

    var vault_file = try std.fs.createFileAbsolute(path, .{
        .read = true,
        .truncate = true,
        .mode = 0o600,
        .exclusive = true,
    });
    defer vault_file.close();

    try vault_file.writeAll("PZP1");

    std.debug.print("Vault created at {s}\n", .{path});
}

pub fn listEntries(allocator: std.mem.Allocator) !void {
    const path = try storage.defaultVaultPath(allocator);
    defer allocator.free(path);

    var file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    var buf: [4]u8 = undefined;
    _ = try file.readAll(&buf);

    std.debug.print("Vault header: {s}\n", .{buf});
}

test "vault init" {
    const allocator = std.testing.allocator;
    try initVault(allocator);
}
