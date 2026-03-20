const std = @import("std");
const config = @import("config.zig");
const v1 = config.v1;
const Vault = @import("vault.zig").Vault;

pub fn serializeVault(allocator: std.mem.Allocator, vault: *Vault) ![]u8 {
    var data = try std.ArrayList(u8).initCapacity(allocator, 1024);
    defer data.deinit(allocator);

    try data.appendSlice(allocator, &vault.header.magic);
    try data.writer(allocator).writeInt(usize, vault.header.version, .little);
    try data.appendSlice(allocator, &vault.header.salt);
    try data.writer(allocator).writeInt(usize, vault.header.iterations, .little);
    try data.writer(allocator).writeInt(u32, vault.header.mem_cost, .little);
    try data.writer(allocator).writeInt(usize, vault.header.parallelism, .little);
    try data.writer(allocator).writeInt(usize, vault.header.entry_count, .little);

    for (vault.entries.items) |entry| {
        try data.writer(allocator).writeInt(u64, entry.id, .little);
        try data.writer(allocator).writeInt(usize, entry.ciphertext.len, .little);
        try data.appendSlice(allocator, &entry.nonce);
        try data.appendSlice(allocator, entry.ciphertext);
        try data.appendSlice(allocator, &entry.tag);
    }
    return data.toOwnedSlice(allocator);
}

pub fn deserializeVault(allocator: std.mem.Allocator, vault: *Vault, bytes: []const u8) !void {
    var r = std.io.Reader.fixed(bytes);

    var magic: [config.MAGIC.len]u8 = undefined;
    try r.readSliceAll(&magic);
    if (!std.mem.eql(u8, &magic, &config.MAGIC)) {
        std.debug.panic("Not pzpazz vault file.\n", .{});
    }

    const version = try r.takeInt(usize, .little);
    if (version != config.VERSION) {
        std.debug.panic("Wrong version of pzpazz vault file.\n", .{});
    }

    var salt: [v1.SALT_LEN]u8 = undefined;
    try r.readSliceAll(&salt);

    const iterations = try r.takeInt(usize, .little);
    const mem_cost = try r.takeInt(u32, .little);
    const parallelism = try r.takeInt(usize, .little);
    const entry_count = try r.takeInt(usize, .little);

    vault.header = Vault.Header{
        .magic = magic,
        .version = version,
        .salt = salt,
        .iterations = iterations,
        .mem_cost = mem_cost,
        .parallelism = parallelism,
        .entry_count = entry_count,
    };
    vault.entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, entry_count);

    for (0..entry_count) |_| {
        const id = try r.takeInt(u64, .little);
        const len = try r.takeInt(usize, .little);

        const nonce = try allocator.alloc(u8, v1.NONCE_LEN);
        defer allocator.free(nonce);
        try r.readSliceAll(nonce);

        const ciphertext = try allocator.alloc(u8, len);
        defer allocator.free(ciphertext);
        try r.readSliceAll(ciphertext);

        const tag = try allocator.alloc(u8, v1.TAG_LEN);
        defer allocator.free(tag);
        try r.readSliceAll(tag);

        const entry: Vault.Entry = .{
            .id = id,
            .len = len,
            .nonce = nonce[0..v1.NONCE_LEN].*,
            .ciphertext = try allocator.dupe(u8, ciphertext),
            .tag = tag[0..v1.TAG_LEN].*,
        };

        try vault.entries.append(allocator, entry);
    }
}

test "serialize deserialize" {
    const allocator = std.testing.allocator;
    const expect = std.testing.expect;
    const expectEqualSlices = std.testing.expectEqualSlices;

    const vault = try Vault.init(allocator);
    defer vault.deinit(allocator);

    for (0..3) |id| {
        const nonce = try allocator.alloc(u8, v1.NONCE_LEN);
        defer allocator.free(nonce);
        const ctext = try allocator.alloc(u8, 100);
        defer allocator.free(ctext);
        const tag = try allocator.alloc(u8, v1.TAG_LEN);
        defer allocator.free(tag);

        std.crypto.random.bytes(nonce);
        std.crypto.random.bytes(ctext);
        std.crypto.random.bytes(tag);

        const entry: Vault.Entry = .{
            .id = id,
            .len = ctext.len,
            .nonce = nonce[0..v1.NONCE_LEN].*,
            .ciphertext = try allocator.dupe(u8, ctext),
            .tag = tag[0..v1.TAG_LEN].*,
        };

        try vault.entries.append(allocator, entry);
    }

    var salt: [v1.SALT_LEN]u8 = undefined;
    std.crypto.random.bytes(&salt);

    vault.header = .{
        .magic = config.MAGIC,
        .version = config.VERSION,
        .salt = salt,
        .iterations = v1.ITERATIONS,
        .mem_cost = v1.MEM_COST,
        .parallelism = v1.PARALLELISM,
        .entry_count = vault.entries.items.len,
    };

    const vault_serialized = try serializeVault(allocator, vault);
    defer allocator.free(vault_serialized);

    const vault_deserialized = try allocator.create(Vault);
    defer vault_deserialized.deinit(allocator);

    try deserializeVault(allocator, vault_deserialized, vault_serialized);

    try expectEqualSlices(u8, &vault_deserialized.header.magic, &config.MAGIC);
    try expectEqualSlices(u8, &vault_deserialized.header.salt, &vault.header.salt);
    try expect(vault_deserialized.header.iterations == vault.header.iterations);
    try expect(vault_deserialized.header.mem_cost == vault.header.mem_cost);
    try expect(vault_deserialized.header.parallelism == vault.header.parallelism);

    for (vault.entries.items, vault_deserialized.entries.items) |entry, ff| {
        try expect(entry.id == ff.id);
        try expect(entry.len == ff.len);
        try expectEqualSlices(u8, &entry.nonce, &ff.nonce);
        try expectEqualSlices(u8, entry.ciphertext, ff.ciphertext);
        try expectEqualSlices(u8, &entry.tag, &ff.tag);
    }

    const storage = @import("storage.zig");

    const file_path = try storage.VaultPath.testing(allocator, "vault.dat");
    defer allocator.free(file_path);

    try storage.writeFile(file_path, vault_serialized);

    const data_from_file = try storage.readFileAlloc(allocator, file_path);
    defer allocator.free(data_from_file);

    const vault_from_file = try allocator.create(Vault);
    defer vault_from_file.deinit(allocator);

    try deserializeVault(allocator, vault_from_file, data_from_file);

    try expectEqualSlices(u8, &vault_from_file.header.magic, &config.MAGIC);
    try expectEqualSlices(u8, &vault_from_file.header.salt, &vault.header.salt);
    try expect(vault_from_file.header.iterations == vault.header.iterations);
    try expect(vault_from_file.header.mem_cost == vault.header.mem_cost);
    try expect(vault_from_file.header.parallelism == vault.header.parallelism);
    try expect(vault_from_file.header.entry_count == vault.header.entry_count);

    for (vault.entries.items, vault_from_file.entries.items) |entry, ff| {
        try expect(entry.id == ff.id);
        try expect(entry.len == ff.len);
        try expectEqualSlices(u8, &entry.nonce, &ff.nonce);
        try expectEqualSlices(u8, entry.ciphertext, ff.ciphertext);
        try expectEqualSlices(u8, &entry.tag, &ff.tag);
    }
}
