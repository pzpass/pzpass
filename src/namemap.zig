const std = @import("std");
const Vault = @import("vault.zig").Vault;
const v1 = @import("config.zig").v1;
const pzcrypt = @import("crypto.zig");

pub const NameIndex = struct {
    map: std.AutoHashMap([32]u8, std.ArrayList(usize)),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) NameIndex {
        return .{
            .map = std.AutoHashMap([32]u8, std.ArrayList(usize)).init(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *NameIndex) void {
        var it = self.map.valueIterator();
        while (it.next()) |list| {
            list.deinit(self.allocator);
        }
        self.map.deinit();
    }

    pub fn insert(self: *NameIndex, key: [32]u8, id: usize) !void {
        var entry = try self.map.getOrPut(key);
        if (!entry.found_existing) {
            entry.value_ptr.* = try std.ArrayList(usize).initCapacity(self.allocator, 1);
        }
        try entry.value_ptr.append(self.allocator, id);
    }

    pub fn get(self: *NameIndex, key: [32]u8) ?[]usize {
        if (self.map.get(key)) |list| {
            return list.items;
        }
        return null;
    }

    pub fn buildEntryNameMap(
        self: *NameIndex,
        vault: *Vault,
        master_key: [v1.KEY_LEN]u8,
    ) !void {
        for (vault.entries.items) |item| {
            const name = try decryptEntryName(item, master_key);
            defer pzcrypt.zeroAndMunlock(name);
            var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&master_key);
            hmac.update(name);
            var hash: [32]u8 = undefined;
            hmac.final(&hash);

            try self.insert(hash, item.id);
        }
    }

    pub fn findEntryIds(self: *NameIndex, name: []const u8, master_key: []const u8) !?std.ArrayList(usize) {
        var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(master_key);
        hmac.update(name);
        var hash: [32]u8 = undefined;
        hmac.final(&hash);

        return self.map.get(hash);
    }

    fn deriveNameKey(master_key: [32]u8) [32]u8 {
        var out: [32]u8 = undefined;

        std.crypto.kdf.hkdf.sha3.HkdfSha3_256.extractAndExpand(
            &out,
            "name-index-key",
            &master_key,
            "",
        );

        return out;
    }
};

// Mock decrypt function
fn decryptEntryName(entry: Vault.Entry, key: [v1.KEY_LEN]u8) ![]u8 {
    if (key.len != 32) {
        return error.WrongKey;
    }
    const name = try std.heap.page_allocator.alloc(u8, entry.ciphertext_name.len);
    try pzcrypt.mlockSlice(name);
    const data = try std.heap.page_allocator.alloc(u8, entry.ciphertext_name.len);
    try pzcrypt.mlockSlice(data);
    // pretend decryption here
    try pzcrypt.decrypt(&entry, key, name, data);
    return name;
}

test "entry map" {
    const allocator = std.testing.allocator;
    const expect = std.testing.expect;

    var vault = try allocator.create(Vault);

    var kek: [v1.KEY_LEN]u8 = undefined;
    try pzcrypt.mlockSlice(&kek);
    defer pzcrypt.zeroAndMunlock(&kek);

    var password_key: [v1.KEY_LEN]u8 = try pzcrypt.deriveKey(allocator, "blue-penguin", &vault.header.salt);
    try pzcrypt.mlockSlice(&password_key);
    defer pzcrypt.zeroAndMunlock(&password_key);

    vault = try Vault.init(allocator, password_key);
    defer vault.deinit(allocator);

    const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    try aead.decrypt(
        &kek,
        &vault.header.kek_ciphertext,
        vault.header.kek_tag,
        "",
        vault.header.kek_nonce,
        password_key,
    );

    std.crypto.secureZero(u8, &password_key);

    var name_index = NameIndex.init(allocator);
    defer name_index.deinit();

    try name_index.buildEntryNameMap(vault, kek);

    var iter = name_index.map.iterator();
    while (iter.next()) |item| {
        try expect(item.key_ptr.*.len == 32);
        try expect(item.value_ptr.items.len > 0);
    }

    const value = try name_index.findEntryIds("non_existent", &kek);
    try expect(value == null);
}
