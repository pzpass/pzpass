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
    key: [32]u8,
    nonce: [12]u8,
    cipher: []u8,
    tag: *[16]u8,
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
    tag: [16]u8,
    key: [32]u8,
    nonce: [12]u8,
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

test "derive key" {
    const derived_key = try deriveKey(std.testing.allocator, "blue-penguin", "orange-tiger");
    try std.testing.expect(derived_key.len == 32);

    const expected_hex = "a244cb38a5b637d6bb111abb9cccebfffb015572f1314ca445ad51f08c82bc0c";
    var expected_bytes: [32]u8 = undefined;
    const result = try std.fmt.hexToBytes(&expected_bytes, expected_hex);
    try std.testing.expect(result.len == 32);

    try std.testing.expectEqualSlices(u8, &expected_bytes, &derived_key);
}
