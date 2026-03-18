const std = @import("std");

pub const VaultPath = struct {
    vault_dir: []const u8,
    filename: []const u8,

    pub fn default(allocator: std.mem.Allocator, filename: ?[]const u8) ![]u8 {
        const home = try std.process.getEnvVarOwned(allocator, "HOME");
        defer allocator.free(home);

        const user = std.process.getEnvVarOwned(allocator, "USER") catch "default";
        defer allocator.free(user);

        var home_dir = try std.fs.openDirAbsolute(home, .{ .access_sub_paths = true });
        home_dir.makeDir(".pzpass") catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => std.debug.print("{}\n", .{err}),
        };

        const actual_filename = filename orelse "vault.dat";
        return std.fmt.allocPrint(
            allocator,
            "{s}/.pzpass/{s}.{s}",
            .{
                home,
                user,
                actual_filename,
            },
        );
    }

    pub fn testing(allocator: std.mem.Allocator, filename: ?[]const u8) ![]u8 {
        const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
        defer allocator.free(cwd);

        const user = std.process.getEnvVarOwned(allocator, "USER") catch "default";
        defer allocator.free(user);

        std.fs.cwd().makeDir("tmp") catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => std.debug.print("{}\n", .{err}),
        };
        const actual_filename = filename orelse "vault.dat";
        return std.fmt.allocPrint(
            allocator,
            "{s}/tmp/{s}.{s}",
            .{
                cwd,
                user,
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

    const user = std.process.getEnvVarOwned(allocator, "USER") catch "default";
    defer allocator.free(user);

    const expected = try std.fmt.allocPrint(
        allocator,
        "{s}/.pzpass/{s}.vault.dat",
        .{ home, user },
    );
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, default_path);
}

test "testing path" {
    const allocator = std.testing.allocator;

    const testing_path = try VaultPath.testing(allocator, "testing.vault.dat");
    defer allocator.free(testing_path);

    const cwd = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd);

    const user = std.process.getEnvVarOwned(allocator, "USER") catch "default";
    defer allocator.free(user);

    const expected = try std.fmt.allocPrint(
        allocator,
        "{s}/tmp/{s}.testing.vault.dat",
        .{ cwd, user },
    );
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(testing_path, expected);
}
