const std = @import("std");
const Vault = @import("vault.zig").Vault;
const v1 = @import("config.zig").v1;
const pzcrtypto = @import("crypto.zig");

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
        master_key: []const u8,
    ) !void {
        for (vault.entries.items) |item| {
            const name = try decryptEntryName(item, master_key);
            defer pzcrtypto.zeroAndMunlock(name);
            var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(master_key);
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
fn decryptEntryName(entry: Vault.Entry, key: []const u8) ![]u8 {
    if (key.len != 32) {
        return error.WrongKey;
    }
    const buf = try std.heap.page_allocator.alloc(u8, entry.ciphertext_name.len);
    try pzcrtypto.mlockSlice(buf);
    // pretend decryption here
    std.mem.copyForwards(u8, buf, entry.ciphertext_name);
    return buf;
}

test "entry map" {
    const allocator = std.testing.allocator;

    var vault = try Vault.init(allocator);
    defer vault.deinit(allocator);

    var derived_key: [v1.KEY_LEN]u8 = try pzcrtypto.deriveKey(std.testing.allocator, "blue-penguin", "orange-tiger");
    try pzcrtypto.mlockSlice(&derived_key);
    defer pzcrtypto.zeroAndMunlock(&derived_key);

    var name_index = NameIndex.init(allocator);
    defer name_index.deinit();

    try name_index.buildEntryNameMap(vault, &derived_key);

    var iter = name_index.map.iterator();
    while (iter.next()) |item| {
        try std.testing.expect(item.key_ptr.*.len == 32);
        try std.testing.expect(item.value_ptr.items.len > 0);
    }

    const value = try name_index.findEntryIds("non_existent", &derived_key);
    try std.testing.expect(value == null);
}
