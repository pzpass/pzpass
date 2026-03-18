const std = @import("std");
const config = @import("config.zig");
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
        try data.appendSlice(allocator, entry.nonce);
        try data.writer(allocator).writeInt(usize, entry.ciphertext.len, .little);
        try data.appendSlice(allocator, entry.ciphertext);
    }
    return data.toOwnedSlice(allocator);
}

pub fn deserializeVault(allocator: std.mem.Allocator, vault: *Vault, bytes: []const u8) !void {
    var r = std.io.Reader.fixed(bytes);

    var magic: [config.MAGIC.len]u8 = undefined;
    try r.readSliceAll(&magic);

    const version = try r.takeInt(usize, .little);

    var salt: [config.SALT_LEN]u8 = undefined;
    try r.readSliceAll(&salt);

    const iterations = try r.takeInt(usize, .little);
    const mem_cost = try r.takeInt(u32, .little);
    const parallelism = try r.takeInt(usize, .little);
    const entry_count = try r.takeInt(usize, .little);

    const entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, entry_count);

    for (entries.items) |*entry| {
        entry.id = try r.takeInt(u64, .little);
        try r.readSliceAll(entry.nonce);

        const len = try r.takeInt(usize, .little);
        entry.ciphertext = try allocator.alloc(u8, len);
        try r.readSliceAll(@constCast(entry.ciphertext));
    }

    vault.header = Vault.Header{
        .magic = magic,
        .version = version,
        .salt = salt,
        .iterations = iterations,
        .mem_cost = mem_cost,
        .parallelism = parallelism,
        .entry_count = entry_count,
    };
    vault.entries = entries;
}

test "serialize deserialize" {
    const allocator = std.testing.allocator;

    const vault = try Vault.init(allocator);
    defer vault.deinit(allocator);

    for (0..3) |id| {
        var nonce: [config.NONCE_LEN]u8 = undefined;
        var ctext: [100]u8 = undefined;

        std.crypto.random.bytes(&nonce);
        std.crypto.random.bytes(&ctext);

        const entry: Vault.Entry = .{
            .id = id,
            .nonce = &nonce,
            .ciphertext = &ctext,
        };

        try vault.entries.append(allocator, entry);
    }

    var salt: [config.SALT_LEN]u8 = undefined;
    std.crypto.random.bytes(&salt);

    vault.header = .{
        .magic = config.MAGIC,
        .version = config.VERSION,
        .salt = salt,
        .iterations = config.ITERATIONS,
        .mem_cost = config.MEM_COST,
        .parallelism = config.PARALLELISM,
        .entry_count = vault.entries.items.len,
    };

    const vault_serialized = try serializeVault(allocator, vault);
    defer allocator.free(vault_serialized);

    const vault_deserialized = try allocator.create(Vault);
    defer vault_deserialized.deinit(allocator);

    try deserializeVault(allocator, vault_deserialized, vault_serialized);

    try std.testing.expectEqualSlices(u8, &vault_deserialized.header.magic, &config.MAGIC);
    try std.testing.expectEqualSlices(u8, &vault_deserialized.header.salt, &vault.header.salt);
    try std.testing.expect(vault_deserialized.header.iterations == vault.header.iterations);
    try std.testing.expect(vault_deserialized.header.mem_cost == vault.header.mem_cost);
    try std.testing.expect(vault_deserialized.header.parallelism == vault.header.parallelism);

    const storage = @import("storage.zig");

    const file_path = try storage.VaultPath.testing(allocator, "testing.vault.dat");
    defer allocator.free(file_path);

    try storage.writeFile(file_path, vault_serialized);

    const data_from_file = try storage.readFileAlloc(allocator, file_path);
    defer allocator.free(data_from_file);

    const vault_from_file = try allocator.create(Vault);
    defer vault_from_file.deinit(allocator);

    try deserializeVault(allocator, vault_from_file, data_from_file);

    try std.testing.expectEqualSlices(u8, &vault_from_file.header.magic, &config.MAGIC);
    try std.testing.expectEqualSlices(u8, &vault_from_file.header.salt, &vault.header.salt);
    try std.testing.expect(vault_from_file.header.iterations == vault.header.iterations);
    try std.testing.expect(vault_from_file.header.mem_cost == vault.header.mem_cost);
    try std.testing.expect(vault_from_file.header.parallelism == vault.header.parallelism);
}
