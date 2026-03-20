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
    plaintext: []const u8,
) void {
    const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    aead.encrypt(
        entry.ciphertext,
        &entry.tag,
        plaintext,
        "",
        entry.nonce,
        key,
    );
}

pub fn decrypt(
    entry: *Vault.Entry,
    key: [v1.KEY_LEN]u8,
    plaintext: []u8,
) !void {
    const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    try aead.decrypt(
        plaintext,
        entry.ciphertext,
        entry.tag,
        "",
        entry.nonce,
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
    const derived_key: [v1.KEY_LEN]u8 = try deriveKey(std.testing.allocator, "blue-penguin", "orange-tiger");
    defer zeroAndMunlock(&derived_key);

    try std.testing.expect(derived_key.len == v1.KEY_LEN);

    const expected_hex = "a244cb38a5b637d6bb111abb9cccebfffb015572f1314ca445ad51f08c82bc0c";

    var expected_bytes: [v1.KEY_LEN]u8 = undefined;

    const result = try std.fmt.hexToBytes(&expected_bytes, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected_bytes, &derived_key);
    try std.testing.expect(result.len == v1.KEY_LEN);

    const testing = std.testing;
    const allocator = testing.allocator;

    const plaintext = "this is a plain text.";
    const entry = try allocator.create(Vault.Entry);
    defer allocator.destroy(entry);

    std.crypto.random.bytes(&entry.nonce);

    entry.ciphertext = try allocator.alloc(u8, plaintext.len);
    defer allocator.free(entry.ciphertext);

    entry.id = std.crypto.random.int(u64);
    entry.len = plaintext.len;

    encrypt(entry, derived_key, plaintext);
    std.debug.print(
        \\ Vault Entry
        \\  id:    {d}
        \\  nonce: {x}
        \\  len:   {d}
        \\  tag:   {x}
        \\  ct:    {x}
        \\
    , .{
        entry.id,
        entry.nonce,
        entry.len,
        entry.tag,
        entry.ciphertext,
    });

    var decrypted: [plaintext.len]u8 = undefined;

    try decrypt(entry, derived_key, &decrypted);

    try std.testing.expectEqualSlices(u8, plaintext, &decrypted);
    std.debug.print("{s}\n", .{decrypted});
}
