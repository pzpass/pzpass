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
        try data.appendSlice(allocator, &entry.nonce);
        try data.writer(allocator).writeInt(usize, entry.ciphertext.len, .little);
        try data.appendSlice(allocator, entry.ciphertext);
    }
    return data.toOwnedSlice(allocator);
}

pub fn deserializeVault(allocator: std.mem.Allocator, bytes: []const u8) !Vault {
    var stream = std.io.fixedBufferStream(bytes);
    const r = stream.reader();

    var magic: [config.MAGIC.len]u8 = undefined;
    try r.readNoEof(&magic);

    const version = try r.readInt(usize, .little);

    var salt: [config.SALT_LEN]u8 = undefined;
    try r.readNoEof(&salt);

    const iterations = try r.readInt(usize, .little);
    const mem_cost = try r.readInt(u32, .little);
    const parallelism = try r.readInt(usize, .little);
    const entry_count = try r.readInt(usize, .little);

    var entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, entry_count);
    defer entries.deinit(allocator);

    for (entries.items) |*entry| {
        entry.id = try r.readInt(u64, .little);
        try r.readNoEof(&entry.nonce);

        const len = try r.readInt(usize, .little);
        entry.ciphertext = try allocator.alloc(u8, len);
        try r.readNoEof(@constCast(entry.ciphertext));
    }

    return Vault{
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

    const ciphertexts = [_][]const u8{ "aaa", "bbb", "ccc" };

    try entries.appendSlice(allocator, &.{
        Vault.Entry{
            .id = 1,
            .nonce = [_]u8{'a'} ** config.NONCE_LEN,
            .ciphertext = ciphertexts[0],
        },
        Vault.Entry{
            .id = 2,
            .nonce = [_]u8{'b'} ** config.NONCE_LEN,
            .ciphertext = ciphertexts[1],
        },
        Vault.Entry{
            .id = 3,
            .nonce = [_]u8{'c'} ** config.NONCE_LEN,
            .ciphertext = ciphertexts[2],
        },
    });

    const vault = Vault{
        .header = .{
            .magic = config.MAGIC,
            .version = config.VERSION,
            .salt = [_]u8{'a'} ** config.SALT_LEN,
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

    const file_path = "./tmp/testing.vault.dat";
    // defer allocator.free(file_path);

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
