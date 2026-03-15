const std = @import("std");
const local = @import("constants.zig");

pub fn randomBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

fn deriveKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
) ![local.KEY_LEN]u8 {
    var key: [local.KEY_LEN]u8 = undefined;
    const locked_key_status = std.os.linux.mlock2(&key, key.len, .{});
    if (locked_key_status != 0) {
        std.debug.print("Cannot mlock key: size {d}\n", .{locked_key_status});
    }

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
    key: []const u8,
    nonce: []const u8,
    plaintext: []const u8,
    out: []u8,
) void {
    const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    aead.encrypt(
        out,
        plaintext,
        &[_]u8{},
        nonce,
        key,
    );
}

fn encryptEntry(
    plaintext: []const u8,
    key: [local.KEY_LEN]u8,
    nonce: [local.NONCE_LEN]u8,
    cipher: []u8,
    tag: *[local.TAG_LEN]u8,
) void {
    std.crypto.aead.chacha_poly.ChaCha20Poly1305.encrypt(
        cipher,
        tag,
        plaintext,
        "",
        nonce,
        key,
    );
}

fn decryptEntry(
    plaintext: []u8,
    cipher: []const u8,
    tag: [local.TAG_LEN]u8,
    key: [local.KEY_LEN]u8,
    nonce: [local.NONCE_LEN]u8,
) !void {
    try std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
        plaintext,
        cipher,
        tag,
        "",
        nonce,
        key,
    );
}

fn zeroAndMunlock(key: [local.KEY_LEN]u8) void {
    std.crypto.secureZero(u8, @constCast(key[0..]));
    const munlock_status = std.os.linux.munlock(&key, key.len);
    if (munlock_status != 0) {
        std.debug.print("Cannot munlock, status: {d}", .{munlock_status});
    }
}

test "derive key" {
    const derived_key: [local.KEY_LEN]u8 = try deriveKey(std.testing.allocator, "blue-penguin", "orange-tiger");
    defer zeroAndMunlock(derived_key);

    try std.testing.expect(derived_key.len == local.KEY_LEN);

    const expected_hex = "a244cb38a5b637d6bb111abb9cccebfffb015572f1314ca445ad51f08c82bc0c";

    var expected_bytes: [local.KEY_LEN]u8 = undefined;

    const result = try std.fmt.hexToBytes(&expected_bytes, expected_hex);
    try std.testing.expectEqualSlices(u8, &expected_bytes, &derived_key);
    try std.testing.expect(result.len == local.KEY_LEN);
}
