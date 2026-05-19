const std = @import("std");

const Allocator = std.mem.Allocator;
const alignment = std.mem.Alignment.fromByteUnits(std.heap.page_size_min);

pub const VaultPath = struct {
    vault_dir: []const u8,
    filename: []const u8,

    pub fn default(
        allocator: Allocator,
        io: std.Io,
        base_dir: []const u8,
        filename: ?[]const u8,
    ) ![]u8 {
        var home_dir = try std.Io.Dir.openDirAbsolute(
            io,
            base_dir,
            .{ .access_sub_paths = true },
        );
        home_dir.createDirPath(io, ".pzpass") catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => std.debug.print("{}\n", .{err}),
        };

        const actual_filename = filename orelse "vault.dat";
        return std.fmt.allocPrint(
            allocator,
            "{s}/.pzpass/{s}",
            .{
                base_dir,
                actual_filename,
            },
        );
    }
};

pub fn readFileAlloc(
    allocator: Allocator,
    io: std.Io,
    base_dir_name: []const u8,
    sub_dir_name: []const u8,
    file_name: []const u8,
) ![]u8 {
    const base_dir = std.Io.Dir.openDirAbsolute(
        io,
        base_dir_name,
        .{ .access_sub_paths = true },
    ) catch |err| {
        return err;
    };
    defer base_dir.close(io);

    const sub_dir = base_dir.openDir(
        io,
        sub_dir_name,
        .{ .access_sub_paths = true },
    ) catch
        try base_dir.createDirPathOpen(io, sub_dir_name, .{});
    defer sub_dir.close(io);

    const file = try sub_dir.openFile(io, file_name, .{});
    defer file.close(io);

    const file_metadata = try file.stat(io);
    if (file_metadata.size == 0) {
        return error.EmptyVault;
    }

    const data_from_file = try allocator.alignedAlloc(u8, alignment, 1 << 20);
    if (file_metadata.size == 0) {
        std.debug.print("{s}/{s}/{s} is empty\n", .{ base_dir_name, sub_dir_name, file_name });
        return data_from_file;
    }
    const file_ptr = try std.posix.mmap(
        null,
        file_metadata.size,
        .{ .READ = true, .WRITE = false },
        .{ .TYPE = .SHARED },
        file.handle,
        0,
    );
    defer std.posix.munmap(file_ptr);
    std.mem.copyForwards(u8, data_from_file, file_ptr);
    return data_from_file;
}

pub fn writeFile(
    allocator: Allocator,
    io: std.Io,
    base_dir_name: []const u8,
    sub_dir_name: []const u8,
    file_name: []const u8,
    data: []const u8,
) !void {
    const base_dir = std.Io.Dir.openDirAbsolute(
        io,
        base_dir_name,
        .{ .access_sub_paths = true },
    ) catch |err| {
        std.debug.panic("Base directory {s} does not exist: {}", .{ base_dir_name, err });
        return err;
    };
    defer base_dir.close(io);

    const sub_dir = try base_dir.openDir(
        io,
        sub_dir_name,
        .{ .access_sub_paths = true },
    );
    defer sub_dir.close(io);

    const bak_name = try std.fmt.allocPrint(allocator, "{s}.bak", .{file_name});
    defer allocator.free(bak_name);

    const tmp_name = try std.fmt.allocPrint(allocator, "{s}.tmp", .{file_name});
    defer allocator.free(tmp_name);

    const perms: std.Io.File.Permissions = @enumFromInt(0o600);
    const tmp_file = try sub_dir.createFile(io, tmp_name, .{ .truncate = true, .permissions = perms });
    defer tmp_file.close(io);

    var buff: [8092]u8 = undefined;

    // std.debug.print("Data: {x}", .{data});
    var file_writer = tmp_file.writer(io, &buff);
    const writer = &file_writer.interface;
    const bytes_written = try writer.write(data);
    if (bytes_written != data.len) {
        std.debug.print("bytes written {d} does not match data size {d}\n", .{ bytes_written, data.len });
    }
    try writer.flush();
    try tmp_file.sync(io);

    if (sub_dir.access(io, file_name, .{})) |_| {
        sub_dir.deleteFile(io, bak_name) catch {};
        try sub_dir.rename(file_name, sub_dir, bak_name, io);
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    try sub_dir.rename(tmp_name, sub_dir, file_name, io);
}

test "default path" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const env = std.testing.environ;

    const home = env.getPosix("HOME") orelse unreachable;

    const default_path = try VaultPath.default(allocator, io, home, "storage.vault.dat");
    defer allocator.free(default_path);

    const expected = try std.fmt.allocPrint(
        allocator,
        "{s}/.pzpass/{s}.vault.dat",
        .{ home, "storage" },
    );
    defer allocator.free(expected);

    try std.testing.expectEqualStrings(expected, default_path);
}

test "testing path" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const env = std.testing.environ;

    const cwd = env.getPosix("PWD") orelse unreachable;

    const testing_path = try VaultPath.default(allocator, io, cwd, "storage.vault.dat");
    defer allocator.free(testing_path);

    const expected = try std.fmt.allocPrint(
        allocator,
        "{s}/.pzpass/storage.vault.dat",
        .{cwd},
    );
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(testing_path, expected);
}

test "store file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const env = std.testing.environ;

    const cwd = env.getPosix("PWD") orelse unreachable;
    try writeFile(allocator, io, cwd, ".pzpass", "mock.stored.file", "asdfgh");
}
