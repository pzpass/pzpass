const std = @import("std");
const config = @import("config.zig");
const Vault = @import("vault.zig").Vault;

pub fn serializeVault(allocator: std.mem.Allocator, vault: *const Vault) ![]u8 {
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

pub fn deserializeVault(allocator: std.mem.Allocator, bytes: []const u8) !Vault {
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

    var entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, entry_count);
    defer entries.deinit(allocator);

    for (entries.items) |*entry| {
        entry.id = try r.takeInt(u64, .little);
        try r.readSliceAll(entry.nonce);

        const len = try r.takeInt(usize, .little);
        entry.ciphertext = try allocator.alloc(u8, len);
        try r.readSliceAll(@constCast(entry.ciphertext));
    }

    return .{
        .header = Vault.Header{
            .magic = magic,
            .version = version,
            .salt = salt,
            .iterations = iterations,
            .mem_cost = mem_cost,
            .parallelism = parallelism,
            .entry_count = entry_count,
        },
        .entries = entries,
    };
}

test "serialize deserialize" {
    const allocator = std.testing.allocator;

    var entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, 0);
    defer entries.deinit(allocator);

    var ciphertexts: [3][100]u8 = undefined;
    var nonces: [3][config.NONCE_LEN]u8 = undefined;
    for (&nonces, &ciphertexts, 0..) |*nonce, *ct, id| {
        std.crypto.random.bytes(nonce);
        std.crypto.random.bytes(ct);

        try entries.appendSlice(allocator, &.{
            Vault.Entry{
                .id = id,
                .nonce = nonce,
                .ciphertext = ct,
            },
        });
    }

    var salt: [config.SALT_LEN]u8 = undefined;
    std.crypto.random.bytes(&salt);

    const vault = Vault{
        .header = .{
            .magic = config.MAGIC,
            .version = config.VERSION,
            .salt = salt,
            .iterations = config.ITERATIONS,
            .mem_cost = config.MEM_COST,
            .parallelism = config.PARALLELISM,
            .entry_count = entries.items.len,
        },
        .entries = entries,
    };

    const vault_serialized = try serializeVault(allocator, &vault);
    defer allocator.free(vault_serialized);

    const vault_deserialized = try deserializeVault(allocator, vault_serialized);

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

    const vault_from_file = try deserializeVault(allocator, data_from_file);

    try std.testing.expectEqualSlices(u8, &vault_from_file.header.magic, &config.MAGIC);
    try std.testing.expectEqualSlices(u8, &vault_from_file.header.salt, &vault.header.salt);
    try std.testing.expect(vault_from_file.header.iterations == vault.header.iterations);
    try std.testing.expect(vault_from_file.header.mem_cost == vault.header.mem_cost);
    try std.testing.expect(vault_from_file.header.parallelism == vault.header.parallelism);
}
