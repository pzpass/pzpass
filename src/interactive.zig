const std = @import("std");

const Vault = @import("vault.zig").Vault;
const takeDelimiter = @import("vault.zig").takeDelimiter;
const flushInput = @import("vault.zig").flushInput;

const termios = @import("termios.zig");
const pzcrypt = @import("crypto.zig");

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const Allocator = std.mem.Allocator;

const posix = std.posix;
var keep_running = std.atomic.Value(bool).init(true);
fn sigIntHandler(sig: posix.SIG) callconv(.c) void {
    _ = sig;
    keep_running.store(false, .monotonic);
}

pub fn run(
    allocator: Allocator,
    io: std.Io,
    options: Vault.Options,
    base_dir_name: []const u8,
    sub_dir_name: []const u8,
    file_name: []const u8,
) !void {
    const out = options.out;
    const in = options.in;
    const prompt_options: Vault.Options = .{
        .out = out,
        .in = in,
    };
    var act: posix.Sigaction = .{
        .handler = .{
            .handler = sigIntHandler,
        },
        .mask = posix.sigemptyset(),
        .flags = 0,
    };
    posix.sigaction(posix.SIG.INT, &act, null);

    var vault_changed = false;
    try out.writeAll("\x1b[?1049h");
    try out.flush();
    defer resetBuffer(out);

    var original_termios: posix.termios = undefined;
    defer termios.reset_terminal(&original_termios);

    try out.writeAll("\x1b[33mPassword:\x1b[0m ");
    try out.flush();

    try termios.set_terminal_pasword(&original_termios);
    const user_password = try takeDelimiter(out, in, '\n');
    try flushInput(out, in);
    termios.reset_terminal(&original_termios);
    try termios.set_terminal(&original_termios);

    try out.writeAll("\n");

    var vault = try allocator.create(Vault);
    errdefer allocator.destroy(vault);

    if (user_password) |password| {
        try pzcrypt.mlockSlice(password);
        defer pzcrypt.zeroAndMunlock(password);

        vault = try Vault.init(
            allocator,
            io,
            password,
            base_dir_name,
            sub_dir_name,
            file_name,
        );

        std.crypto.secureZero(u8, password);
    } else {
        try out.writeAll("Null password is not valid.");
    }
    defer vault.deinit(allocator);

    while (keep_running.load(.monotonic)) {
        try flushInput(out, in);
        try Vault.short_help(out);

        try in.fillMore();
        const key = try in.takeByte();
        switch (key) {
            '\n', '\r' => {},
            27, 'q' => break,
            'a' => {
                termios.reset_terminal(&original_termios);

                vault_changed = try vault.addEntryPrompt(allocator, io, prompt_options) or vault_changed;

                try termios.set_terminal(&original_termios);
            },
            'e' => {
                termios.reset_terminal(&original_termios);

                vault_changed = try vault.editEntryPrompt(allocator, io, prompt_options) or vault_changed;

                try termios.set_terminal(&original_termios);
            },
            'g' => {
                termios.reset_terminal(&original_termios);

                vault_changed = try vault.addPasswordPrompt(allocator, io, prompt_options) or vault_changed;

                try termios.set_terminal(&original_termios);
            },
            'd' => {
                termios.reset_terminal(&original_termios);

                vault_changed = try vault.deleteEntryPrompt(allocator, prompt_options) or vault_changed;

                try termios.set_terminal(&original_termios);
            },
            'l' => {
                try vault.listEntries(allocator, out, null);
            },
            'f' => {
                termios.reset_terminal(&original_termios);

                try vault.findEntryPrompt(allocator, prompt_options);

                try termios.set_terminal(&original_termios);
            },
            'o' => {
                termios.reset_terminal(&original_termios);

                try vault.openEntryPrompt(allocator, prompt_options);

                try termios.set_terminal(&original_termios);
            },
            'u' => {
                termios.reset_terminal(&original_termios);
                try termios.set_terminal_pasword(&original_termios);

                vault_changed = try vault.updatePasswordPrompt(allocator, io, prompt_options) or vault_changed;

                termios.reset_terminal(&original_termios);
                try termios.set_terminal(&original_termios);
            },
            'i' => {
                try vault.info(out);
            },
            's' => {
                try vault.save(allocator, io, base_dir_name, sub_dir_name, file_name);
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
            else => try vault.save(allocator, io, base_dir_name, sub_dir_name, file_name),
        }
    }
}

fn resetBuffer(out: *Writer) void {
    out.writeAll("\x1b[?1049l") catch {};
    out.flush() catch {};
}
