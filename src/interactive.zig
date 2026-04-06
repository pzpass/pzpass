const std = @import("std");

const Vault = @import("vault.zig").Vault;
const takeDelimiter = @import("vault.zig").takeDelimiter;
const flushInput = @import("vault.zig").flushInput;

const termios = @import("termios.zig");
const pzcrypt = @import("crypto.zig");

const Reader = std.io.Reader;
const Writer = std.io.Writer;

const Allocator = std.mem.Allocator;

pub fn run(
    allocator: Allocator,
    out: *Writer,
    in: *Reader,
) !void {
    var vault_changed = false;

    var original_termios: std.os.linux.termios = undefined;
    defer termios.reset_terminal(&original_termios);

    var vault = try allocator.create(Vault);
    defer vault.deinit(allocator);

    try out.writeAll("\x1b[33mPassword:\x1b[0m ");
    try out.flush();

    try termios.set_terminal_pasword(&original_termios);
    const user_password = try takeDelimiter(out, in, '\n');
    try flushInput(out, in);
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

    while (true) {
        try flushInput(out, in);
        try Vault.short_help(out);

        try in.fillMore();
        const key = try in.takeByte();
        switch (key) {
            '\n', '\r' => {},
            27, 'q' => break,
            'a' => {
                termios.reset_terminal(&original_termios);

                try vault.addEntryPrompt(allocator, out, in);
                vault_changed = true;

                try termios.set_terminal(&original_termios);
            },
            'e' => {
                termios.reset_terminal(&original_termios);

                try vault.editEntryPrompt(allocator, out, in);
                vault_changed = true;

                try termios.set_terminal(&original_termios);
            },
            'g' => {
                termios.reset_terminal(&original_termios);

                try vault.addPasswordPrompt(allocator, out, in);
                vault_changed = true;

                try termios.set_terminal(&original_termios);
            },
            'd' => {
                termios.reset_terminal(&original_termios);

                try vault.deleteEntryPrompt(allocator, out, in);
                vault_changed = true;

                try termios.set_terminal(&original_termios);
            },
            'l' => {
                try vault.listEntries(allocator, out, null);
            },
            'f' => {
                termios.reset_terminal(&original_termios);

                try vault.findEntryPrompt(allocator, out, in);

                try termios.set_terminal(&original_termios);
            },
            'o' => {
                termios.reset_terminal(&original_termios);

                try vault.openEntryPrompt(allocator, out, in);

                try termios.set_terminal(&original_termios);
            },
            'u' => {
                termios.reset_terminal(&original_termios);
                try termios.set_terminal_pasword(&original_termios);

                try vault.updatePasswordPrompt(allocator, out, in);
                vault_changed = true;

                termios.reset_terminal(&original_termios);
                try termios.set_terminal(&original_termios);
            },
            'i' => {
                try vault.info(out);
            },
            's' => {
                try vault.save(allocator);
                try out.writeAll("\x1b[33mVault saved to disk.\x1b[0m\n");
                vault_changed = false;
            },
            'h' => {
                try Vault.help(out);
            },
            else => {},
        }
        try out.flush();
    }

    if (vault_changed) {
        try out.writeAll("\x1b[33mSave vault? [Y/n]]\x1b[0m\n");
        try out.flush();

        try in.fillMore();
        const confirm = try in.takeByte();
        switch (confirm) {
            'n', 'N' => {},
            else => try vault.save(allocator),
        }
    }

    try out.flush();
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
