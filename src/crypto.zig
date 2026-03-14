const std = @import("std");

pub fn randomBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

pub fn deriveKey(
    password: []const u8,
    salt: []const u8,
    out: []u8,
) !void {
    try std.crypto.pwhash.argon2.kdf(
        out,
        password,
        salt,
        .{},
    );
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
