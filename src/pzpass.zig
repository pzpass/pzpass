const std = @import("std");

const dice = @import("dicephrase.zig");
const Vault = @import("vault.zig").Vault;
const interactive = @import("interactive.zig");
const pzcrypt = @import("crypto.zig");

const passwordgen = @import("passwordgen.zig");

pub fn run() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const stdout_buff: []u8 = try allocator.alloc(u8, Vault.ENTRY_LEN);
    defer allocator.free(stdout_buff);
    try pzcrypt.mlockSlice(@constCast(stdout_buff));
    defer pzcrypt.zeroAndMunlock(stdout_buff);

    var stdout = std.fs.File.stdout().writer(stdout_buff);
    const out = &stdout.interface;

    const stdin_buff: []u8 = try allocator.alloc(u8, Vault.ENTRY_LEN);
    defer allocator.free(stdin_buff);

    var stdin_reader = std.fs.File.stdin().reader(stdin_buff);
    const stdin = &stdin_reader.interface;
    try pzcrypt.mlockSlice(@constCast(stdin_buff));
    defer pzcrypt.zeroAndMunlock(stdin_buff);

    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2) {
        interactive.run(allocator, out, stdin) catch {
            try out.writeAll("\x1b[?1049l");
            try out.flush();
        };
        return;
    }
    defer std.process.argsFree(allocator, args);

    const cmd = args[1];

    if (std.mem.startsWith(u8, "dicephrase", cmd)) {
        try dice.runPassphraseGenerator(allocator, out, stdin, args);
    } else if (std.mem.startsWith(u8, "password", cmd)) {
        try passwordgen.runPasswordGenerator(allocator, out, args);
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
        \\
    , .{});
}

test "vault" {
    const allocator = std.testing.allocator;

    var vault = try Vault.init(allocator, "blue-penguin");
    defer vault.deinit(allocator);
}
