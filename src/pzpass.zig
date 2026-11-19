const std = @import("std");

const dice = @import("dicephrase.zig");
const Vault = @import("vault.zig").Vault;
const interactive = @import("interactive.zig");
const pzcrypt = @import("crypto.zig");

const passwordgen = @import("passwordgen.zig");

pub fn run(init: std.process.Init) !void {
    // Not the arena: frees must actually release memory in a long TUI session,
    // and in debug builds this allocator also reports leaks and bad frees.
    const allocator = init.gpa;

    // Terminal I/O carries passwords and entry data, so both buffers are secrets.
    const stdout_buff = try pzcrypt.allocSecret(allocator, Vault.ENTRY_LEN);
    defer pzcrypt.freeSecret(allocator, stdout_buff);

    var stdout_file = std.Io.File.stdout().writer(init.io, stdout_buff);
    const stdout = &stdout_file.interface;

    const stdin_buff = try pzcrypt.allocSecret(allocator, Vault.ENTRY_LEN);
    defer pzcrypt.freeSecret(allocator, stdin_buff);

    var stdin_reader = std.Io.File.stdin().reader(init.io, stdin_buff);
    const stdin = &stdin_reader.interface;

    const prompt_options: Vault.Options = .{
        .out = stdout,
        .in = stdin,
    };

    const args = try init.minimal.args.toSlice(allocator);
    defer allocator.free(args);

    if (args.len < 2) {
        const home_dir = init.minimal.environ.getPosix("HOME") orelse return error.MissingHomeEnv;
        const username = init.minimal.environ.getPosix("USER") orelse return error.MissingUserEnv;
        const vault_path = try allocator.print(
            "{s}.vault.dat",
            .{username},
        );
        defer allocator.free(vault_path);
        try interactive.run(
            allocator,
            init.io,
            prompt_options,
            home_dir,
            ".pzpass",
            vault_path,
        );
        return;
    }

    const cmd = args[1];

    if (std.mem.startsWith(u8, "dicephrase", cmd)) {
        try dice.runPassphraseGenerator(allocator, init.io, stdout, stdin, args);
    } else if (std.mem.startsWith(u8, "password", cmd)) {
        try passwordgen.runPasswordGenerator(allocator, init.io, stdout, args);
    } else if (args.len > 2 and std.mem.eql(u8, "-f", cmd)) {
        const home_dir = init.minimal.environ.getPosix("HOME") orelse return error.MissingHomeEnv;
        const file_name = if (args[2].len > 0) args[2] else return error.NoFileNameGiven;
        try interactive.run(allocator, init.io, prompt_options, home_dir, ".pzpass", file_name);
        return;
    } else {
        try printUsage();
        std.process.exit(2);
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
    const io = std.testing.io;
    const environ = std.testing.environ;

    const cwd = environ.getPosix("PWD") orelse "/tmp";
    var vault = try Vault.init(allocator, io, "blue-penguin", cwd, ".pzpass", "test.vault.dat");
    defer vault.deinit(allocator);
}
