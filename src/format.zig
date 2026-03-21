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
    try data.writer(allocator).writeInt(usize, vault.entries.items.len, .little);
    try data.writer(allocator).writeInt(usize, vault.entries.items.len, .little); // double for control

    for (vault.entries.items) |entry| {
        try data.writer(allocator).writeInt(u64, entry.id, .little);

        try data.writer(allocator).writeInt(usize, entry.ciphertext_name.len, .little);
        try data.writer(allocator).writeInt(usize, entry.ciphertext_data.len, .little);

        try data.appendSlice(allocator, &entry.nonce_name);
        try data.appendSlice(allocator, &entry.nonce_data);

        try data.appendSlice(allocator, entry.ciphertext_name);
        try data.appendSlice(allocator, entry.ciphertext_data);

        try data.appendSlice(allocator, &entry.tag_name);
        try data.appendSlice(allocator, &entry.tag_data);
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
    const contr_count = try r.takeInt(usize, .little);
    if (entry_count != contr_count) {
        return error.EntryCountNotMatch;
    }

    vault.header = Vault.Header{
        .magic = magic,
        .version = version,
        .salt = salt,
        .iterations = iterations,
        .mem_cost = mem_cost,
        .parallelism = parallelism,
    };
    vault.entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, entry_count);

    for (0..entry_count) |_| {
        const id = try r.takeInt(u64, .little);

        const name_len = try r.takeInt(u64, .little);
        const data_len = try r.takeInt(u64, .little);

        const nonce_name = try allocator.alloc(u8, v1.NONCE_LEN);
        defer allocator.free(nonce_name);
        try r.readSliceAll(nonce_name);

        const nonce_data = try allocator.alloc(u8, v1.NONCE_LEN);
        defer allocator.free(nonce_data);
        try r.readSliceAll(nonce_data);

        const ciphertext_name = try allocator.alloc(u8, name_len);
        defer allocator.free(ciphertext_name);
        try r.readSliceAll(ciphertext_name);

        const ciphertext_data = try allocator.alloc(u8, data_len);
        defer allocator.free(ciphertext_data);
        try r.readSliceAll(ciphertext_data);

        const tag_name = try allocator.alloc(u8, v1.TAG_LEN);
        defer allocator.free(tag_name);
        try r.readSliceAll(tag_name);

        const tag_data = try allocator.alloc(u8, v1.TAG_LEN);
        defer allocator.free(tag_data);
        try r.readSliceAll(tag_data);

        const entry: Vault.Entry = .{
            .id = id,
            .tag_name = tag_name[0..v1.TAG_LEN].*,
            .tag_data = tag_data[0..v1.TAG_LEN].*,
            .nonce_name = nonce_name[0..v1.NONCE_LEN].*,
            .nonce_data = nonce_data[0..v1.NONCE_LEN].*,
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
    const expect = std.testing.expect;
    const expectEqualSlices = std.testing.expectEqualSlices;

    const vault = try Vault.init(allocator);
    defer vault.deinit(allocator);

    for (0..3) |id| {
        const nonce_name = try allocator.alloc(u8, v1.NONCE_LEN);
        defer allocator.free(nonce_name);

        const nonce_data = try allocator.alloc(u8, v1.NONCE_LEN);
        defer allocator.free(nonce_data);

        const ciphertext_name = try allocator.alloc(u8, 100);
        defer allocator.free(ciphertext_name);

        const ciphertext_data = try allocator.alloc(u8, 100);
        defer allocator.free(ciphertext_data);

        const tag_name = try allocator.alloc(u8, v1.TAG_LEN);
        defer allocator.free(tag_name);

        const tag_data = try allocator.alloc(u8, v1.TAG_LEN);
        defer allocator.free(tag_data);

        std.crypto.random.bytes(nonce_name);
        std.crypto.random.bytes(nonce_data);

        std.crypto.random.bytes(ciphertext_name);
        std.crypto.random.bytes(ciphertext_data);

        std.crypto.random.bytes(tag_name);
        std.crypto.random.bytes(tag_data);

        const entry: Vault.Entry = .{
            .id = id,
            .nonce_name = nonce_name[0..v1.NONCE_LEN].*,
            .nonce_data = nonce_data[0..v1.NONCE_LEN].*,
            .ciphertext_name = try allocator.dupe(u8, ciphertext_name),
            .ciphertext_data = try allocator.dupe(u8, ciphertext_data),
            .tag_name = tag_name[0..v1.TAG_LEN].*,
            .tag_data = tag_data[0..v1.TAG_LEN].*,
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
        try expectEqualSlices(u8, &entry.nonce_name, &ff.nonce_name);
        try expectEqualSlices(u8, entry.ciphertext_name, ff.ciphertext_name);
        try expectEqualSlices(u8, &entry.tag_name, &ff.tag_name);
        try expectEqualSlices(u8, &entry.nonce_data, &ff.nonce_data);
        try expectEqualSlices(u8, entry.ciphertext_data, ff.ciphertext_data);
        try expectEqualSlices(u8, &entry.tag_data, &ff.tag_data);
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

    for (vault.entries.items, vault_from_file.entries.items) |entry, ff| {
        try expect(entry.id == ff.id);
        try expectEqualSlices(u8, &entry.nonce_name, &ff.nonce_name);
        try expectEqualSlices(u8, entry.ciphertext_name, ff.ciphertext_name);
        try expectEqualSlices(u8, &entry.tag_name, &ff.tag_name);
        try expectEqualSlices(u8, &entry.nonce_data, &ff.nonce_data);
        try expectEqualSlices(u8, entry.ciphertext_data, ff.ciphertext_data);
        try expectEqualSlices(u8, &entry.tag_data, &ff.tag_data);
    }
}
