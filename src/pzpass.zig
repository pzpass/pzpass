const std = @import("std");

const dice = @import("dicephrase.zig");
const Vault = @import("vault.zig").Vault;
const interactive = @import("interactive.zig");
const pzcrypt = @import("crypto.zig");

const passwordgen = @import("passwordgen.zig");

pub fn run(init: std.process.Init) !void {
    const allocator = init.arena.allocator();

    const stdout_buff: []u8 = try allocator.alloc(u8, Vault.ENTRY_LEN);
    try pzcrypt.mlockSlice(stdout_buff);
    defer {
        pzcrypt.zeroAndMunlock(stdout_buff);
        allocator.free(stdout_buff);
    }

    var stdout_file = std.Io.File.stdout().writer(init.io, stdout_buff);
    const stdout = &stdout_file.interface;

    const stdin_buff: []u8 = try allocator.alloc(u8, Vault.ENTRY_LEN);
    defer allocator.free(stdin_buff);

    var stdin_reader = std.Io.File.stdin().reader(init.io, stdin_buff);
    const stdin = &stdin_reader.interface;
    try pzcrypt.mlockSlice(stdin_buff);
    defer {
        pzcrypt.zeroAndMunlock(stdin_buff);
        allocator.free(stdin_buff);
    }

    const prompt_options: Vault.Options = .{
        .out = stdout,
        .in = stdin,
    };

    const home_dir = init.minimal.environ.getPosix("HOME") orelse undefined;
    const username = init.minimal.environ.getPosix("USER") orelse undefined;
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2) {
        const vault_path = try std.fmt.allocPrint(
            allocator,
            "{s}.vault.dat",
            .{username},
        );
        interactive.run(
            allocator,
            init.io,
            prompt_options,
            home_dir,
            ".pzpass",
            vault_path,
        ) catch |err| {
            try stdout.writeAll("\x1b[?1049l");
            try stdout.flush();
            return err;
        };
        return;
    }
    defer allocator.free(args);

    const cmd = args[1];

    if (std.mem.startsWith(u8, "dicephrase", cmd)) {
        try dice.runPassphraseGenerator(allocator, init.io, stdout, stdin, args);
    } else if (std.mem.startsWith(u8, "password", cmd)) {
        try passwordgen.runPasswordGenerator(allocator, init.io, stdout, args);
    } else if (std.mem.eql(u8, "-f", cmd)) {
        const file_name = if (args[2].len > 0) args[2] else return error.NoFileNameGiven;
        interactive.run(allocator, init.io, prompt_options, home_dir, ".pzpass", file_name) catch |err| {
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
    const io = std.testing.io;
    const environ = std.testing.environ;

    const cwd = environ.getPosix("PWD") orelse unreachable;
    var vault = try Vault.init(allocator, io, "blue-penguin", cwd, ".pzpass", "test.vault.dat");
    defer vault.deinit(allocator);
}
