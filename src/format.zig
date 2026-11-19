const std = @import("std");

const Allocator = std.mem.Allocator;

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

const MAGIC = @import("config.zig").MAGIC;
const Config = @import("config.zig").Config;
const Vault = @import("vault.zig").Vault;
const pzcrypt = @import("crypto.zig");

const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

/// HMAC-SHA256 over the serialized vault (everything before the MAC), keyed
/// with a subkey of the vault key. Detects deleted, reordered, duplicated or
/// altered entries without decrypting any of them.
fn fileMac(vault_key: *const pzcrypt.Key, body: []const u8) [Config.MAC_LEN]u8 {
    var mac_key: [Hmac.key_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &mac_key);
    Hmac.create(&mac_key, "pzpass v3 file mac", vault_key);

    var mac: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&mac, body, &mac_key);
    return mac;
}

/// Checks the trailing MAC of a v3 file. Needs the unwrapped vault key.
pub fn verifyMac(vault_key: *const pzcrypt.Key, bytes: []const u8) !void {
    if (bytes.len < Config.MAC_LEN) return error.VaultMacMismatch;
    const body_len = bytes.len - Config.MAC_LEN;
    const expected = fileMac(vault_key, bytes[0..body_len]);
    const actual = bytes[body_len..][0..Config.MAC_LEN].*;
    if (!std.crypto.timing_safe.eql([Config.MAC_LEN]u8, expected, actual)) {
        return error.VaultMacMismatch;
    }
}

/// Always writes the current format (`Config.VERSION`); older vaults are
/// migrated in memory when they are opened.
pub fn serializeVault(allocator: Allocator, vault: *Vault) ![]u8 {
    if (vault.header.version != Config.VERSION) return error.UnsupportedVersion;

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
    try data.appendSlice(allocator, &vault.header.vault_id);
    std.mem.writeInt(usize, &buff, vault.entries.items.len, .little);
    try data.appendSlice(allocator, &buff);
    std.mem.writeInt(usize, &buff, vault.entries.items.len, .little);
    try data.appendSlice(allocator, &buff);

    for (vault.entries.items) |entry| {
        try data.appendSlice(allocator, &entry.id);
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

    const mac = fileMac(vault.vault_key, data.items);
    try data.appendSlice(allocator, &mac);
    return data.toOwnedSlice(allocator);
}

pub fn deserializeVault(allocator: Allocator, vault: *Vault, bytes: []const u8) !void {
    var r = Reader.fixed(bytes);

    var magic: [MAGIC.len]u8 = undefined;
    try r.readSliceAll(&magic);
    if (!std.mem.eql(u8, &magic, &MAGIC)) {
        return error.InvalidMagic;
    }

    const version = try r.takeInt(usize, .little);
    if (version < 1 or version > Config.VERSION) {
        return error.InvalidVersion;
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

    var vault_id = std.mem.zeroes([Config.ID_LEN]u8);
    if (version >= 3) try r.readSliceAll(&vault_id);

    const entry_count = try r.takeInt(usize, .little);
    const contr_count = try r.takeInt(usize, .little);
    if (entry_count != contr_count) {
        return error.EntryCountNotMatch;
    }

    // Bound the allocation below by what the file can actually hold.
    const id_len: usize = if (version >= 3) Config.ID_LEN else 0;
    const min_entry_size = id_len + 2 * @sizeOf(usize) + 2 * Config.NONCE_LEN + 2 * Config.TAG_LEN;
    if (entry_count > r.bufferedLen() / min_entry_size) {
        return error.InvalidEntryCount;
    }

    vault.header = Vault.Header{
        .magic = magic,
        .version = version,
        .salt = salt,
        // Not yet authenticated: reject instead of truncating (or worse, in
        // release builds without safety checks).
        .iterations = std.math.cast(u32, iterations) orelse return error.InvalidHeader,
        .mem_cost = mem_cost,
        .parallelism = std.math.cast(u32, parallelism) orelse return error.InvalidHeader,
        .kek_nonce = nonce,
        .kek_ciphertext = kek_ciphertext,
        .kek_tag = tag,
        .vault_id = vault_id,
    };
    vault.entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, entry_count);

    const max_entry_size = 1 << 24;

    for (0..entry_count) |_| {
        var entry_id = std.mem.zeroes([Config.ID_LEN]u8);
        if (version >= 3) try r.readSliceAll(&entry_id);

        const name_len = try r.takeInt(usize, .little);
        const data_len = try r.takeInt(usize, .little);

        if (name_len > max_entry_size or data_len > max_entry_size) {
            return error.EntryTooLarge;
        }

        var nonce_name: [Config.NONCE_LEN]u8 = undefined;
        try r.readSliceAll(&nonce_name);

        var nonce_data: [Config.NONCE_LEN]u8 = undefined;
        try r.readSliceAll(&nonce_data);

        const ciphertext_name = try allocator.alloc(u8, name_len);
        errdefer allocator.free(ciphertext_name);
        try r.readSliceAll(ciphertext_name);

        const ciphertext_data = try allocator.alloc(u8, data_len);
        errdefer allocator.free(ciphertext_data);
        try r.readSliceAll(ciphertext_data);

        var tag_name: [Config.TAG_LEN]u8 = undefined;
        try r.readSliceAll(&tag_name);

        var tag_data: [Config.TAG_LEN]u8 = undefined;
        try r.readSliceAll(&tag_data);

        const entry: Vault.Entry = .{
            .id = entry_id,
            .nonce_name = nonce_name,
            .nonce_data = nonce_data,
            .ciphertext_name = ciphertext_name,
            .ciphertext_data = ciphertext_data,
            .tag_name = tag_name,
            .tag_data = tag_data,
        };

        try vault.entries.append(allocator, entry);
    }
    if (vault.entries.items.len != entry_count) {
        return error.RecoveredVaultEntriesSizeNotMatch;
    }
    // v3: exactly the MAC must remain (it is checked once the key is unwrapped).
    if (version >= 3 and r.bufferedLen() != Config.MAC_LEN) {
        return error.InvalidVaultSize;
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

    const home = env.getPosix("PWD") orelse "/tmp";
    const sub_dir_name = ".pzpass";
    const file_name = "format.vault.dat";

    var vault = try Vault.init(
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
        defer pzcrypt.freeSecret(allocator, name);

        const data = try dice.generateDicePhrase(allocator, io, 50);
        defer pzcrypt.freeSecret(allocator, data);

        try vault.addEntry(allocator, io, name, data);
    }

    for (0..3) |_| {
        const name = try pass.generate(allocator, io, Vault.ENTRY_LEN);
        defer pzcrypt.freeSecret(allocator, name);

        const data = try pass.generate(allocator, io, Vault.ENTRY_LEN);
        defer pzcrypt.freeSecret(allocator, data);

        try vault.addEntry(allocator, io, name, data);
    }

    const vault_serialized = try serializeVault(allocator, vault);
    defer allocator.free(vault_serialized);

    const vault_deserialized = try Vault.createEmpty(
        allocator,
        try allocator.print("{s}/{s}/{s}", .{ home, sub_dir_name, file_name }),
    );
    defer vault_deserialized.deinit(allocator);

    try deserializeVault(allocator, vault_deserialized, vault_serialized);
    try verifyMac(vault.vault_key, vault_serialized);

    // Flipping any byte of the file breaks the MAC.
    vault_serialized[vault_serialized.len / 2] ^= 1;
    try std.testing.expectError(error.VaultMacMismatch, verifyMac(vault.vault_key, vault_serialized));
    vault_serialized[vault_serialized.len / 2] ^= 1;

    try expectEqualSlices(u8, &vault_deserialized.header.magic, &MAGIC);
    try expectEqualSlices(u8, &vault_deserialized.header.vault_id, &vault.header.vault_id);
    try expectEqualSlices(u8, &vault_deserialized.header.salt, &vault.header.salt);
    try expectEqualSlices(u8, &vault_deserialized.header.kek_ciphertext, &vault.header.kek_ciphertext);
    try expectEqualSlices(u8, &vault_deserialized.header.kek_nonce, &vault.header.kek_nonce);
    try expectEqualSlices(u8, &vault_deserialized.header.kek_tag, &vault.header.kek_tag);
    try expect(vault_deserialized.header.iterations == vault.header.iterations);
    try expect(vault_deserialized.header.mem_cost == vault.header.mem_cost);
    try expect(vault_deserialized.header.parallelism == vault.header.parallelism);

    for (vault.entries.items, vault_deserialized.entries.items) |entry, ff| {
        try expectEqualSlices(u8, &entry.id, &ff.id);
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

    const vault_from_file = try Vault.createEmpty(
        allocator,
        try allocator.print("{s}/{s}/{s}", .{ home, sub_dir_name, file_name }),
    );
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
        try expectEqualSlices(u8, &entry.id, &ff.id);
        try expectEqualSlices(u8, &entry.nonce_name, &ff.nonce_name);
        try expectEqualSlices(u8, entry.ciphertext_name, ff.ciphertext_name);
        try expectEqualSlices(u8, &entry.tag_name, &ff.tag_name);
        try expectEqualSlices(u8, &entry.nonce_data, &ff.nonce_data);
        try expectEqualSlices(u8, entry.ciphertext_data, ff.ciphertext_data);
        try expectEqualSlices(u8, &entry.tag_data, &ff.tag_data);
    }
}
