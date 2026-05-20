const std = @import("std");
const Vault = @import("vault.zig").Vault;
const Config = @import("config.zig").Config;
const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;

pub fn randomBytes(buf: []u8) void {
    std.crypto.random.bytes(buf);
}

pub fn deriveKey(
    allocator: Allocator,
    io: std.Io,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    mem_cost: u32,
    parallelism: u32,
) ![Config.KEY_LEN]u8 {
    var key: [Config.KEY_LEN]u8 = undefined;
    try mlockSlice(&key);
    defer zeroAndMunlock(&key);

    try std.crypto.pwhash.argon2.kdf(
        allocator,
        &key,
        password,
        salt,
        .{
            .t = iterations,
            .m = mem_cost,
            .p = @intCast(parallelism),
        },
        .argon2id,
        io,
    );

    return key;
}

pub fn encrypt(
    entry: *Vault.Entry,
    key: [Config.KEY_LEN]u8,
    name: []const u8,
    data: []const u8,
) void {
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
        data,
        "",
        entry.nonce_data,
        key,
    );
}

pub fn decrypt(
    entry: *const Vault.Entry,
    key: [Config.KEY_LEN]u8,
    name: []u8,
    data: []u8,
) !void {
    try aead.decrypt(
        name,
        entry.ciphertext_name,
        entry.tag_name,
        "",
        entry.nonce_name,
        key,
    );

    try aead.decrypt(
        data,
        entry.ciphertext_data,
        entry.tag_data,
        "",
        entry.nonce_data,
        key,
    );
}

pub fn mlockSlice(key: []u8) !void {
    if (builtin.os.tag == .linux) {
        const locked_key_status = std.os.linux.mlock2(key.ptr, key.len, .{});
        if (locked_key_status != 0) {
            std.debug.print("Cannot mlock key: size {d}\n", .{locked_key_status});
            return error.NotMlocked;
        }
    }
}

pub fn zeroAndMunlock(key: []u8) void {
    std.crypto.secureZero(u8, key[0..]);
    if (builtin.os.tag == .linux) {
        const munlock_status = std.os.linux.munlock(key.ptr, key.len);
        if (munlock_status != 0) {
            std.debug.print("Cannot munlock, status: {d}", .{munlock_status});
        }
    }
}

test "derive key" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const expect = std.testing.expect;
    const expectEqualSlices = std.testing.expectEqualSlices;

    var derived_key: [Config.KEY_LEN]u8 = try deriveKey(
        allocator,
        io,
        "blue-penguin",
        "orange-tiger",
        Config.ITERATIONS,
        Config.MEM_COST,
        Config.PARALLELISM,
    );
    defer zeroAndMunlock(&derived_key);

    try expect(derived_key.len == Config.KEY_LEN);

    const expected_hex_string = "f04524de367275272bc296fe7aa7ac2b9aaecff4da5fb8b3c20a292134dca379";
    const derived_key_string = std.fmt.bytesToHex(&derived_key, .lower);
    try expectEqualSlices(u8, &derived_key_string, expected_hex_string);

    const entry = try allocator.create(Vault.Entry);
    defer allocator.destroy(entry);

    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    rng.bytes(&entry.nonce_name);
    rng.bytes(&entry.nonce_data);

    const name = "plain text";
    entry.ciphertext_name = try allocator.alloc(u8, name.len);
    defer allocator.free(entry.ciphertext_name);

    const data = "this is a plain text.";
    entry.ciphertext_data = try allocator.alloc(u8, data.len);
    defer allocator.free(entry.ciphertext_data);

    encrypt(entry, derived_key, name, data);

    var decrypted_name: [name.len]u8 = undefined;
    var decrypted_data: [data.len]u8 = undefined;

    try decrypt(entry, derived_key, &decrypted_name, &decrypted_data);

    try expectEqualSlices(u8, data, &decrypted_data);
    try expectEqualSlices(u8, name, &decrypted_name);
}
