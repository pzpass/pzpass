const std = @import("std");
const dice = @import("dicephrase.zig");

const Vault = @import("vault.zig").Vault;
const storage = @import("storage.zig");
const format = @import("format.zig");

const passwordgen = @import("passwordgen.zig");

pub fn run() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var out_buff: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&out_buff);
    const out = &stdout.interface;

    var stdin_buff: [256]u8 = undefined;
    var stdin_reader = std.fs.File.stdin().reader(&stdin_buff);
    const stdin = &stdin_reader.interface;

    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2) {
        try printUsage();
        return;
    }
    defer std.process.argsFree(allocator, args);

    const cmd = args[1];

    if (std.mem.startsWith(u8, "dicephrase", cmd)) {
        try dice.runPassphraseGenerator(allocator, out, stdin, args);
    } else if (std.mem.startsWith(u8, "password", cmd)) {
        try passwordgen.runPasswordGenerator(allocator, out, args);
    } else if (std.mem.startsWith(u8, "initiate", cmd)) {
        const vault = try Vault.init(allocator);
        defer vault.deinit(allocator);

        const file_path = try storage.VaultPath.default(allocator, null);
        defer allocator.free(file_path);

        const vault_serialized = try format.serializeVault(allocator, vault);
        defer allocator.free(vault_serialized);

        try storage.writeFile(file_path, vault_serialized);
    } else {
        try printUsage();
    }

    try out.flush();
}

fn printUsage() !void {
    std.debug.print(
        \\pzp - pEasy password manager
        \\
        \\Commands:
        \\  dice [word_count]        Generate a dice passphrase
        \\  pass [password_length]   Generate a secure password
        \\  init
        \\  list
        \\  add <name>
        \\  get <name>
        \\  delete <name>
        \\
    , .{});
}

test "init vault" {
    const vault = try Vault.init(std.testing.allocator);
    defer vault.deinit(std.testing.allocator);
}
