const std = @import("std");

const Allocator = std.mem.Allocator;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const MAGIC = @import("config.zig").MAGIC;
const Config = @import("config.zig").Config;
const Vault = @import("vault.zig").Vault;
const pzcrypt = @import("crypto.zig");

pub fn serializeVault(allocator: Allocator, vault: *Vault) ![]u8 {
    var data = try std.ArrayList(u8).initCapacity(allocator, 1024);
    defer data.deinit(allocator);

    try data.appendSlice(allocator, &vault.header.magic);
    var buff: [@sizeOf(usize)]u8 = undefined;
    std.mem.writeInt(usize, &buff, vault.header.version, .little);
    try data.appendSlice(allocator, &buff);
    try data.appendSlice(allocator, &vault.header.salt);
    std.mem.writeInt(usize, &buff, vault.header.iterations, .little);
    try data.appendSlice(allocator, &buff);
    var buff_u32: [@sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, &buff_u32, vault.header.mem_cost, .little);
    try data.appendSlice(allocator, &buff_u32);
    std.mem.writeInt(usize, &buff, vault.header.parallelism, .little);
    try data.appendSlice(allocator, &buff);
    try data.appendSlice(allocator, &vault.header.kek_nonce);
    try data.appendSlice(allocator, &vault.header.kek_ciphertext);
    try data.appendSlice(allocator, &vault.header.kek_tag);
    std.mem.writeInt(usize, &buff, vault.entries.items.len, .little);
    try data.appendSlice(allocator, &buff);
    std.mem.writeInt(usize, &buff, vault.entries.items.len, .little);
    try data.appendSlice(allocator, &buff);

    for (vault.entries.items) |entry| {
        std.mem.writeInt(usize, &buff, entry.ciphertext_name.len, .little);
        try data.appendSlice(allocator, &buff);
        std.mem.writeInt(usize, &buff, entry.ciphertext_data.len, .little);
        try data.appendSlice(allocator, &buff);

        try data.appendSlice(allocator, &entry.nonce_name);
        try data.appendSlice(allocator, &entry.nonce_data);

        try data.appendSlice(allocator, entry.ciphertext_name);
        try data.appendSlice(allocator, entry.ciphertext_data);

        try data.appendSlice(allocator, &entry.tag_name);
        try data.appendSlice(allocator, &entry.tag_data);
    }
    return data.toOwnedSlice(allocator);
}

pub fn deserializeVault(allocator: Allocator, vault: *Vault, bytes: []const u8) !void {
    var r = Reader.fixed(bytes);

    var magic: [MAGIC.len]u8 = undefined;
    try r.readSliceAll(&magic);
    if (!std.mem.eql(u8, &magic, &MAGIC)) {
        std.debug.panic("Not pzpass vault file.\n", .{});
    }

    const version = try r.takeInt(usize, .little);
    if (version != Config.VERSION) {
        std.debug.panic("Wrong version of pzpazz vault file.\n", .{});
    }

    var salt: [Config.SALT_LEN]u8 = undefined;
    try r.readSliceAll(&salt);

    const iterations = try r.takeInt(usize, .little);
    const mem_cost = try r.takeInt(u32, .little);
    const parallelism = try r.takeInt(usize, .little);

    var nonce: [Config.NONCE_LEN]u8 = undefined;
    try r.readSliceAll(&nonce);

    var kek_ciphertext: [Config.KEY_LEN]u8 = undefined;
    try r.readSliceAll(&kek_ciphertext);

    var tag: [Config.TAG_LEN]u8 = undefined;
    try r.readSliceAll(&tag);

    const entry_count = try r.takeInt(usize, .little);
    const contr_count = try r.takeInt(usize, .little);
    if (entry_count != contr_count) {
        return error.EntryCountNotMatch;
    }

    vault.header = Vault.Header{
        .magic = magic,
        .version = version,
        .salt = salt,
        .iterations = @intCast(iterations),
        .mem_cost = mem_cost,
        .parallelism = @intCast(parallelism),
        .kek_nonce = nonce,
        .kek_ciphertext = kek_ciphertext,
        .kek_tag = tag,
    };
    vault.entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, entry_count);

    for (0..entry_count) |_| {
        const name_len = try r.takeInt(usize, .little);
        const data_len = try r.takeInt(usize, .little);

        const nonce_name = try allocator.alloc(u8, Config.NONCE_LEN);
        defer allocator.free(nonce_name);
        try r.readSliceAll(nonce_name);

        const nonce_data = try allocator.alloc(u8, Config.NONCE_LEN);
        defer allocator.free(nonce_data);
        try r.readSliceAll(nonce_data);

        const ciphertext_name = try allocator.alloc(u8, name_len);
        defer allocator.free(ciphertext_name);
        try r.readSliceAll(ciphertext_name);

        const ciphertext_data = try allocator.alloc(u8, data_len);
        defer allocator.free(ciphertext_data);
        try r.readSliceAll(ciphertext_data);

        const tag_name = try allocator.alloc(u8, Config.TAG_LEN);
        defer allocator.free(tag_name);
        try r.readSliceAll(tag_name);

        const tag_data = try allocator.alloc(u8, Config.TAG_LEN);
        defer allocator.free(tag_data);
        try r.readSliceAll(tag_data);

        const entry: Vault.Entry = .{
            .tag_name = tag_name[0..Config.TAG_LEN].*,
            .tag_data = tag_data[0..Config.TAG_LEN].*,
            .nonce_name = nonce_name[0..Config.NONCE_LEN].*,
            .nonce_data = nonce_data[0..Config.NONCE_LEN].*,
            .ciphertext_name = try allocator.dupe(u8, ciphertext_name),
            .ciphertext_data = try allocator.dupe(u8, ciphertext_data),
        };

        try vault.entries.append(allocator, entry);
    }
    if (vault.entries.items.len != entry_count) {
        return error.RecoveredVaultEntriesSizeNotMatch;
    }
}

test "serialize deserialize" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const env = std.testing.environ;
    const expect = std.testing.expect;
    const expectEqualSlices = std.testing.expectEqualSlices;

    const dice = @import("dicephrase.zig");
    const pass = @import("passwordgen.zig");
    const storage = @import("storage.zig");

    const home = env.getPosix("PWD") orelse unreachable;
    const sub_dir_name = ".pzpass";
    const file_name = "format.vault.dat";

    const vault = try Vault.init(
        allocator,
        io,
        "blue-penguin",
        home,
        sub_dir_name,
        file_name,
    );
    defer vault.deinit(allocator);

    for (0..3) |_| {
        const name = try dice.generateDicePhrase(allocator, io, 20);
        defer allocator.free(name);

        const data = try dice.generateDicePhrase(allocator, io, 50);
        defer allocator.free(data);

        try vault.addEntry(allocator, io, name, data);
    }

    for (0..3) |_| {
        const name = try pass.generate(allocator, io, Vault.ENTRY_LEN);
        defer allocator.free(name);

        const data = try pass.generate(allocator, io, Vault.ENTRY_LEN);
        defer allocator.free(data);

        try vault.addEntry(allocator, io, name, data);
    }

    const vault_serialized = try serializeVault(allocator, vault);
    defer allocator.free(vault_serialized);

    const vault_deserialized = try allocator.create(Vault);
    defer vault_deserialized.deinit(allocator);

    try deserializeVault(allocator, vault_deserialized, vault_serialized);

    try expectEqualSlices(u8, &vault_deserialized.header.magic, &MAGIC);
    try expectEqualSlices(u8, &vault_deserialized.header.salt, &vault.header.salt);
    try expectEqualSlices(u8, &vault_deserialized.header.kek_ciphertext, &vault.header.kek_ciphertext);
    try expectEqualSlices(u8, &vault_deserialized.header.kek_nonce, &vault.header.kek_nonce);
    try expectEqualSlices(u8, &vault_deserialized.header.kek_tag, &vault.header.kek_tag);
    try expect(vault_deserialized.header.iterations == vault.header.iterations);
    try expect(vault_deserialized.header.mem_cost == vault.header.mem_cost);
    try expect(vault_deserialized.header.parallelism == vault.header.parallelism);

    for (vault.entries.items, vault_deserialized.entries.items) |entry, ff| {
        try expectEqualSlices(u8, &entry.nonce_name, &ff.nonce_name);
        try expectEqualSlices(u8, entry.ciphertext_name, ff.ciphertext_name);
        try expectEqualSlices(u8, &entry.tag_name, &ff.tag_name);
        try expectEqualSlices(u8, &entry.nonce_data, &ff.nonce_data);
        try expectEqualSlices(u8, entry.ciphertext_data, ff.ciphertext_data);
        try expectEqualSlices(u8, &entry.tag_data, &ff.tag_data);
    }

    try storage.writeFile(allocator, io, home, sub_dir_name, file_name, vault_serialized);

    const data_from_file = try storage.readFileAlloc(allocator, io, home, sub_dir_name, file_name);
    defer allocator.free(data_from_file);

    const vault_from_file = try allocator.create(Vault);
    defer vault_from_file.deinit(allocator);

    try deserializeVault(allocator, vault_from_file, data_from_file);

    try expectEqualSlices(u8, &vault_from_file.header.magic, &MAGIC);
    try expectEqualSlices(u8, &vault_from_file.header.salt, &vault.header.salt);
    try expectEqualSlices(u8, &vault_from_file.header.kek_ciphertext, &vault.header.kek_ciphertext);
    try expectEqualSlices(u8, &vault_from_file.header.kek_nonce, &vault.header.kek_nonce);
    try expectEqualSlices(u8, &vault_from_file.header.kek_tag, &vault.header.kek_tag);
    try expect(vault_from_file.header.iterations == vault.header.iterations);
    try expect(vault_from_file.header.mem_cost == vault.header.mem_cost);
    try expect(vault_from_file.header.parallelism == vault.header.parallelism);

    for (vault.entries.items, vault_from_file.entries.items) |entry, ff| {
        try expectEqualSlices(u8, &entry.nonce_name, &ff.nonce_name);
        try expectEqualSlices(u8, entry.ciphertext_name, ff.ciphertext_name);
        try expectEqualSlices(u8, &entry.tag_name, &ff.tag_name);
        try expectEqualSlices(u8, &entry.nonce_data, &ff.nonce_data);
        try expectEqualSlices(u8, entry.ciphertext_data, ff.ciphertext_data);
        try expectEqualSlices(u8, &entry.tag_data, &ff.tag_data);
    }
}
