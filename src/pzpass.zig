const std = @import("std");
const dice = @import("dicephrase.zig");

const vault = @import("vault.zig");
const passwordgen = @import("passwordgen.zig");

pub fn run() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var out_buff: [4096]u8 = undefined;
    var stdout = std.fs.File.stdout().writer(&out_buff);
    const out = &stdout.interface;

    const args = try std.process.argsAlloc(allocator);
    if (args.len < 2) {
        try printUsage();
        return;
    }
    defer std.process.argsFree(allocator, args);

    const cmd = args[1];

    if (std.mem.eql(u8, cmd, "dice")) {
        const word_count = if (args.len > 2)
            std.fmt.parseInt(usize, args[2], 10) catch 5
        else
            5;
        const dicephrase = try dice.generateDicePhrase(allocator, word_count);
        defer allocator.free(dicephrase);
        try out.print("{s}\n", .{dicephrase});
    } else if (std.mem.eql(u8, cmd, "gen")) {
        const password_length = if (args.len > 2)
            std.fmt.parseInt(usize, args[2], 10) catch 20
        else
            20;
        const pw = try passwordgen.generate(allocator, password_length);
        defer allocator.free(pw);
        try out.print("{s}\n", .{pw});
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
        \\  dice [word_count]       Generate a dice passphrase
        \\  gen [password_length]   Generate a secure password
        \\  init
        \\  list
        \\  add <name>
        \\  get <name>
        \\  delete <name>
        \\
    , .{});
}

test "dummy" {
    try std.testing.expect(true);
}
