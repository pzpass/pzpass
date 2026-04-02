const std = @import("std");

const Vault = @import("vault.zig").Vault;
const NameIndex = @import("namemap.zig").NameIndex;
const v1 = @import("config.zig").v1;

const format = @import("format.zig");
const storage = @import("storage.zig");
const termios = @import("termios.zig");
const pzcrypt = @import("crypto.zig");

pub fn run(
    allocator: std.mem.Allocator,
    out: *std.io.Writer,
    in: *std.io.Reader,
) !void {
    var original_termios: std.os.linux.termios = undefined;
    defer termios.reset_terminal(&original_termios);

    var vault = try allocator.create(Vault);
    defer vault.deinit(allocator);

    try out.writeAll("\x1b[33mPassword:\x1b[0m ");
    try out.flush();

    try termios.set_terminal_pasword(&original_termios);
    const user_password = try in.takeDelimiter('\n');
    termios.reset_terminal(&original_termios);
    try termios.set_terminal(&original_termios);

    try out.writeAll("\n");

    if (user_password) |password| {
        try pzcrypt.mlockSlice(password);
        defer pzcrypt.zeroAndMunlock(password);

        vault = try Vault.init(allocator, password);

        std.crypto.secureZero(u8, password);
    } else {
        try out.writeAll("Null password is not valid.");
    }

    var name_index = NameIndex.init(allocator);
    defer name_index.deinit();

    try name_index.buildEntryNameMap(vault);
    try vault.listEntries(allocator, out, null);

    const file_path = try storage.VaultPath.default(allocator, null);
    defer allocator.free(file_path);

    var show_help_enabled = true;

    while (true) {
        try in.fillMore();
        const key = try in.takeByte();
        switch (key) {
            '\n', '\r' => {},
            27, 'q' => break,
            'a' => {
                termios.reset_terminal(&original_termios);

                try vault.addEntryInteractive(allocator, out, in);

                try termios.set_terminal(&original_termios);
            },
            'd' => {
                termios.reset_terminal(&original_termios);

                try vault.deleteEntryInteractive(allocator, out, in);

                try termios.set_terminal(&original_termios);
            },
            'l' => {
                try vault.listEntries(allocator, out, null);
            },
            'f' => {
                termios.reset_terminal(&original_termios);

                try vault.findEntryInteractive(allocator, out, in);

                try termios.set_terminal(&original_termios);
            },
            'o' => {
                termios.reset_terminal(&original_termios);

                try vault.openEntryInteractive(allocator, out, in);

                try termios.set_terminal(&original_termios);
            },
            'u' => {
                termios.reset_terminal(&original_termios);
                try termios.set_terminal_pasword(&original_termios);

                try vault.updatePasswordInteractive(allocator, out, in);

                termios.reset_terminal(&original_termios);
                try termios.set_terminal(&original_termios);
            },
            'i' => {
                try out.print("\x1b[33mVault stored as:\n{s}\x1b[0m\n", .{file_path});
            },
            's' => {
                try vault.save(allocator, file_path);
                try out.writeAll("\x1b[33mVault saved to disk.\x1b[0m\n");
            },
            'h' => {
                try Vault.help(out);
                show_help_enabled = false;
            },
            else => show_help_enabled = try show_help(show_help_enabled, out),
        }
        try out.flush();
    }

    try vault.save(allocator, file_path);

    try out.flush();
}

fn show_help(enabled: bool, out: *std.io.Writer) !bool {
    if (enabled) {
        try Vault.help(out);
    }
    return false;
}

test "try run" {
    var out_buff: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&out_buff);
    const out = &stdout.interface;

    var stdin_buff: [256]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buff);
    const stdin = &stdin_reader.interface;

    try run(std.testing.allocator, out, stdin);
}
