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

    var stdout_file = std.fs.File.stdout().writer(stdout_buff);
    const stdout = &stdout_file.interface;

    const stdin_buff: []u8 = try allocator.alloc(u8, Vault.ENTRY_LEN);
    defer allocator.free(stdin_buff);

    var stdin_reader = std.fs.File.stdin().reader(stdin_buff);
    const stdin = &stdin_reader.interface;
    try pzcrypt.mlockSlice(@constCast(stdin_buff));
    defer pzcrypt.zeroAndMunlock(stdin_buff);

    const prompt_options: Vault.Options = .{
        .out = stdout,
        .in = stdin,
    };

    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2) {
        interactive.run(allocator, prompt_options, null) catch |err| {
            try stdout.writeAll("\x1b[?1049l");
            try stdout.flush();
            return err;
        };
        return;
    }
    defer std.process.argsFree(allocator, args);

    const cmd = args[1];

    if (std.mem.startsWith(u8, "dicephrase", cmd)) {
        try dice.runPassphraseGenerator(allocator, stdout, stdin, args);
    } else if (std.mem.startsWith(u8, "password", cmd)) {
        try passwordgen.runPasswordGenerator(allocator, stdout, args);
    } else if (std.mem.eql(u8, "-f", cmd)) {
        const vault_path = if (args[2].len > 0) args[2] else return error.NoFileNameGiven;
        interactive.run(allocator, prompt_options, vault_path) catch |err| {
            try stdout.writeAll("\x1b[?1049l");
            try stdout.flush();
            return err;
        };
        return;
    } else {
        try printUsage();
    }

    try stdout.flush();
}

fn printUsage() !void {
    std.debug.print(
        \\pEasy password manager
        \\pzp [ -f <vault_file_name>]
        \\
        \\Commands:
        \\  dice [word_count]        Generate a dice passphrase
        \\  pass [password_length]   Generate a secure password
        \\
    , .{});
}

test "vault" {
    const allocator = std.testing.allocator;

    var vault = try Vault.init(allocator, "blue-penguin", "test.vault.dat");
    defer vault.deinit(allocator);
}
