const std = @import("std");
const sha256 = std.crypto.hash.sha2.Sha256;
const Vault = @import("vault.zig").Vault;
const v1 = @import("config.zig").v1;
const pzcrtypto = @import("crypto.zig");

pub fn buildEntryNameMap(allocator: std.mem.Allocator, vault: *Vault, master_key: []const u8) !std.AutoHashMap([32]u8, u64) {
    var map = std.AutoHashMap([32]u8, u64).init(allocator);

    for (vault.entries.items) |item| {
        const name = try decryptEntryName(item, master_key);
        var hmac = sha256.init(.{});
        hmac.update(name);
        var hash: [32]u8 = undefined;
        hmac.final(&hash);

        try map.put(hash, item.id);

        std.crypto.secureZero(u8, name);
    }

    return map;
}

// pub fn findEntryId(map: *std.AutoHashMap([32]u8, usize), master_key: []const u8, requested_name: []const u8) !?usize {
//     var hmac = try crypto.hmac.init(crypto.sha256, master_key);
//     try hmac.update(requested_name);
//     var hash = hmac.final();
//
//     return map.get(hash);
// }

// Mock decrypt function (replace with your ChaCha20-Poly1305 decryption)
fn decryptEntryName(entry: Vault.Entry, key: []const u8) ![]u8 {
    if (key.len != 32) {
        return error.WrongKey;
    }
    const buf = try std.heap.page_allocator.alloc(u8, entry.ciphertext_name.len);
    // pretend decryption here
    std.mem.copyForwards(u8, buf, entry.ciphertext_name);
    return buf;
}

test "entry map" {
    const allocator = std.testing.allocator;

    var vault = try Vault.init(allocator);
    defer vault.deinit(allocator);

    const derived_key: [v1.KEY_LEN]u8 = try pzcrtypto.deriveKey(std.testing.allocator, "blue-penguin", "orange-tiger");
    defer pzcrtypto.zeroAndMunlock(&derived_key);

    var name_map = try buildEntryNameMap(allocator, vault, &derived_key);
    defer name_map.deinit();

    var iter = name_map.iterator();
    while (iter.next()) |item| {
        try std.testing.expect(item.key_ptr.*.len == 32);
    }
}
