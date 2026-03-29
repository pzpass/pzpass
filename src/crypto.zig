const std = @import("std");
const Vault = @import("vault.zig").Vault;
const v1 = @import("config.zig").v1;

pub fn randomBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

pub fn deriveKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
) ![v1.KEY_LEN]u8 {
    var key: [v1.KEY_LEN]u8 = undefined;
    try mlockSlice(&key);

    try std.crypto.pwhash.argon2.kdf(
        allocator,
        &key,
        password,
        salt,
        .{
            .t = 3,
            .m = 65536,
            .p = 1,
        },
        .argon2id,
    );

    return key;
}

pub fn encrypt(
    entry: *Vault.Entry,
    key: [v1.KEY_LEN]u8,
    name: []const u8,
    plaintext: []const u8,
) void {
    const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    aead.encrypt(
        entry.ciphertext_name,
        &entry.tag_name,
        name,
        "",
        entry.nonce_name,
        key,
    );

    aead.encrypt(
        entry.ciphertext_data,
        &entry.tag_data,
        plaintext,
        "",
        entry.nonce_data,
        key,
    );
}

pub fn decrypt(
    entry: *const Vault.Entry,
    key: [v1.KEY_LEN]u8,
    name: []u8,
    plaintext: []u8,
) !void {
    const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    try aead.decrypt(
        name,
        entry.ciphertext_name,
        entry.tag_name,
        "",
        entry.nonce_name,
        key,
    );

    try aead.decrypt(
        plaintext,
        entry.ciphertext_data,
        entry.tag_data,
        "",
        entry.nonce_data,
        key,
    );
}

pub fn mlockSlice(key: []u8) !void {
    const locked_key_status = std.os.linux.mlock2(key.ptr, key.len, .{});
    if (locked_key_status != 0) {
        std.debug.print("Cannot mlock key: size {d}\n", .{locked_key_status});
        return error.NotMlocked;
    }
}

pub fn zeroAndMunlock(key: []const u8) void {
    std.crypto.secureZero(u8, @constCast(key[0..]));
    const munlock_status = std.os.linux.munlock(key.ptr, key.len);
    if (munlock_status != 0) {
        std.debug.print("Cannot munlock, status: {d}", .{munlock_status});
    }
}

test "derive key" {
    const allocator = std.testing.allocator;
    const expect = std.testing.expect;
    const expectEqualSlices = std.testing.expectEqualSlices;

    const derived_key: [v1.KEY_LEN]u8 = try deriveKey(allocator, "blue-penguin", "orange-tiger");
    defer zeroAndMunlock(&derived_key);

    try expect(derived_key.len == v1.KEY_LEN);

    const expected_hex = "a244cb38a5b637d6bb111abb9cccebfffb015572f1314ca445ad51f08c82bc0c";

    var expected_bytes: [v1.KEY_LEN]u8 = undefined;

    const result = try std.fmt.hexToBytes(&expected_bytes, expected_hex);
    try expectEqualSlices(u8, &expected_bytes, &derived_key);
    try expect(result.len == v1.KEY_LEN);

    const entry = try allocator.create(Vault.Entry);
    defer allocator.destroy(entry);

    std.crypto.random.bytes(&entry.nonce_name);
    std.crypto.random.bytes(&entry.nonce_data);

    const name = "plain text";
    entry.ciphertext_name = try allocator.alloc(u8, name.len);
    defer allocator.free(entry.ciphertext_name);

    const data = "this is a plain text.";
    entry.ciphertext_data = try allocator.alloc(u8, data.len);
    defer allocator.free(entry.ciphertext_data);

    entry.id = std.crypto.random.int(usize);

    encrypt(entry, derived_key, name, data);

    var decrypted_name: [name.len]u8 = undefined;
    var decrypted_data: [data.len]u8 = undefined;

    try decrypt(entry, derived_key, &decrypted_name, &decrypted_data);

    try expectEqualSlices(u8, data, &decrypted_data);
    try expectEqualSlices(u8, name, &decrypted_name);
}
