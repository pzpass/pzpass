const std = @import("std");

const Vault = @import("vault.zig").Vault;
const NameIndex = @import("namemap.zig").NameIndex;
const v1 = @import("config.zig").v1;

const format = @import("format.zig");
const storage = @import("storage.zig");
const termios = @import("termios.zig");
const pzcrtypto = @import("crypto.zig");

pub fn run(
    allocator: std.mem.Allocator,
    out: *std.io.Writer,
    in: *std.io.Reader,
) !void {
    var vault = try Vault.init(allocator);
    defer vault.deinit(allocator);

    var original_termios: std.os.linux.termios = undefined;
    try termios.set_terminal(&original_termios);
    defer termios.reset_terminal(&original_termios);

    try out.writeAll("Password: ");
    try out.flush();

    var derived_key: [v1.KEY_LEN]u8 = undefined;
    try pzcrtypto.mlockSlice(&derived_key);
    defer pzcrtypto.zeroAndMunlock(&derived_key);

    const master_key = try in.takeDelimiter('\n');

    try out.writeAll("\n\n");

    if (master_key) |key| {
        derived_key = try pzcrtypto.deriveKey(allocator, key, &vault.header.salt);
        std.crypto.secureZero(u8, key);
    } else {
        try out.writeAll("Null password is not valid.");
    }

    var name_index = NameIndex.init(allocator);
    defer name_index.deinit();

    try name_index.buildEntryNameMap(vault, derived_key);
    try vault.listEntries(allocator, derived_key, out);

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
                try out.writeAll("Add an entry.\n");
                try out.flush();
            },
            'l' => {
                try vault.listEntries(allocator, derived_key, out);
            },
            'i' => {
                try out.print("Vault stored as:\n{s}\n", .{file_path});
                try out.flush();
            },
            'h' => {
                try Vault.help(out);
                show_help_enabled = false;
            },
            else => show_help_enabled = try show_help(show_help_enabled, out),
        }
    }

    const vault_serialized = try format.serializeVault(allocator, vault);
    defer allocator.free(vault_serialized);

    try out.flush();

    try storage.writeFile(file_path, vault_serialized);
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
