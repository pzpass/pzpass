const std = @import("std");
const Vault = @import("vault.zig").Vault;
const Config = @import("config.zig").Config;
const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const argon2 = std.crypto.pwhash.argon2;

pub const Key = [Config.KEY_LEN]u8;

/// Derives the password key into `out`, which should live in a `Secret`
/// (see `allocKey`).
pub fn deriveKey(
    allocator: Allocator,
    io: std.Io,
    out: *Key,
    password: []const u8,
    salt: []const u8,
    iterations: u32,
    mem_cost: u32,
    parallelism: u32,
) !void {
    const params: argon2.Params = .{
        .t = iterations,
        .m = mem_cost,
        .p = std.math.cast(u24, parallelism) orelse return error.WeakParameters,
    };
    // `calcSize` divides by `p`, so reject what `kdf` would reject before sizing.
    if (params.t < 1 or params.p < 1 or params.m / 8 < params.p) return error.WeakParameters;

    // Argon2's working memory is derived from the password, and std frees it
    // without wiping it. Hand it a buffer we wipe ourselves. (At 256 MiB it is
    // too large to mlock.)
    const scratch = try allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), argon2.calcSize(params));
    defer {
        std.crypto.secureZero(u8, scratch);
        allocator.free(scratch);
    }
    var scratch_allocator = std.heap.FixedBufferAllocator.init(scratch);

    try argon2.kdf(scratch_allocator.allocator(), out, password, salt, params, .argon2id, io);
}

const ENTRY_AD_LEN = Config.ID_LEN * 2 + 1;

/// Associated data for one field of a v3 entry: vault id ‖ entry id ‖ field label.
/// Binds the name and the data to each other and to this vault, so ciphertexts
/// can't be swapped between entries, fields or vaults. A null vault id means a
/// v1/v2 entry, which was encrypted without associated data.
fn entryAd(
    buf: *[ENTRY_AD_LEN]u8,
    vault_id: ?*const [Config.ID_LEN]u8,
    entry_id: *const [Config.ID_LEN]u8,
    label: u8,
) []const u8 {
    const vid = vault_id orelse return buf[0..0];
    buf[0..Config.ID_LEN].* = vid.*;
    buf[Config.ID_LEN..][0..Config.ID_LEN].* = entry_id.*;
    buf[2 * Config.ID_LEN] = label;
    return buf;
}

// Keys are passed by pointer so they are not copied into every stack frame;
// std's AEAD API still takes them by value, so a transient copy remains there.
pub fn encrypt(
    entry: *Vault.Entry,
    key: *const Key,
    vault_id: *const [Config.ID_LEN]u8,
    name: []const u8,
    data: []const u8,
) void {
    var ad: [ENTRY_AD_LEN]u8 = undefined;
    aead.encrypt(
        entry.ciphertext_name,
        &entry.tag_name,
        name,
        entryAd(&ad, vault_id, &entry.id, 'n'),
        entry.nonce_name,
        key.*,
    );

    aead.encrypt(
        entry.ciphertext_data,
        &entry.tag_data,
        data,
        entryAd(&ad, vault_id, &entry.id, 'd'),
        entry.nonce_data,
        key.*,
    );
}

/// Decrypts only the name, leaving the entry's secret data encrypted.
pub fn decryptName(
    entry: *const Vault.Entry,
    key: *const Key,
    vault_id: ?*const [Config.ID_LEN]u8,
    name: []u8,
) !void {
    var ad: [ENTRY_AD_LEN]u8 = undefined;
    try aead.decrypt(
        name,
        entry.ciphertext_name,
        entry.tag_name,
        entryAd(&ad, vault_id, &entry.id, 'n'),
        entry.nonce_name,
        key.*,
    );
}

pub fn decrypt(
    entry: *const Vault.Entry,
    key: *const Key,
    vault_id: ?*const [Config.ID_LEN]u8,
    name: []u8,
    data: []u8,
) !void {
    try decryptName(entry, key, vault_id, name);

    var ad: [ENTRY_AD_LEN]u8 = undefined;
    try aead.decrypt(
        data,
        entry.ciphertext_data,
        entry.tag_data,
        entryAd(&ad, vault_id, &entry.id, 'd'),
        entry.nonce_data,
        key.*,
    );
}

/// Memory for anything sensitive (keys, passwords, plaintext, terminal I/O).
///
/// Every secret gets its own page-aligned allocation, so it never shares a
/// page with other data. That matters because mlock does not nest: unlocking
/// one buffer unlocks its whole page, including any other secret on it. Use
/// only `allocSecret`/`dupeSecret`/`allocKey` to create one and `freeSecret`
/// to release it; the slice type keeps the alignment, so frees are correct.
pub const Secret = []align(std.heap.page_size_min) u8;

/// Page-aligned, mlocked buffer. Release with `freeSecret`.
pub fn allocSecret(allocator: Allocator, len: usize) !Secret {
    const buf = try allocator.alignedAlloc(u8, .fromByteUnits(std.heap.page_size_min), len);
    errdefer allocator.free(buf);
    try mlockSlice(buf);
    return buf;
}

/// Copies `bytes` into a new `Secret`. The caller still has to wipe the source.
pub fn dupeSecret(allocator: Allocator, bytes: []const u8) !Secret {
    const buf = try allocSecret(allocator, bytes.len);
    @memcpy(buf, bytes);
    return buf;
}

/// A `Secret` sized for one key; `buf[0..Config.KEY_LEN]` is the key.
pub fn allocKey(allocator: Allocator) !Secret {
    return allocSecret(allocator, Config.KEY_LEN);
}

pub fn freeSecret(allocator: Allocator, buf: Secret) void {
    zeroAndMunlock(buf);
    allocator.free(buf);
}

/// Prefer `allocSecret`; locking memory that shares pages with other data
/// is undone when any of it is unlocked.
pub fn mlockSlice(buf: []u8) !void {
    if (builtin.target.os.tag == .linux) {
        const rc = std.os.linux.mlock2(buf.ptr, buf.len, .{});
        if (rc != 0) {
            std.debug.print("Cannot mlock {d} bytes: {t} (check RLIMIT_MEMLOCK)\n", .{ buf.len, std.os.linux.errno(rc) });
            return error.NotMlocked;
        }
    }
}

pub fn zeroAndMunlock(buf: []u8) void {
    std.crypto.secureZero(u8, buf);
    if (builtin.target.os.tag == .linux) {
        const rc = std.os.linux.munlock(buf.ptr, buf.len);
        if (rc != 0) {
            std.debug.print("Cannot munlock {d} bytes: {t}\n", .{ buf.len, std.os.linux.errno(rc) });
        }
    }
}

test "derive key" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const expect = std.testing.expect;
    const expectEqualSlices = std.testing.expectEqualSlices;

    const key_buf = try allocKey(allocator);
    defer freeSecret(allocator, key_buf);
    const derived_key = key_buf[0..Config.KEY_LEN];
    try deriveKey(
        allocator,
        io,
        derived_key,
        "blue-penguin",
        "orange-tiger",
        Config.ITERATIONS,
        Config.MEM_COST,
        Config.PARALLELISM,
    );

    try expect(derived_key.len == Config.KEY_LEN);

    // Same result as before routing Argon2 through our own scratch buffer.
    const expected_hex_string = "f04524de367275272bc296fe7aa7ac2b9aaecff4da5fb8b3c20a292134dca379";
    const derived_key_string = std.fmt.bytesToHex(derived_key, .lower);
    try expectEqualSlices(u8, &derived_key_string, expected_hex_string);

    const entry = try allocator.create(Vault.Entry);
    defer allocator.destroy(entry);

    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();

    rng.bytes(&entry.nonce_name);
    rng.bytes(&entry.nonce_data);
    rng.bytes(&entry.id);

    var vault_id: [Config.ID_LEN]u8 = undefined;
    rng.bytes(&vault_id);

    const name = "plain text";
    entry.ciphertext_name = try allocator.alloc(u8, name.len);
    defer allocator.free(entry.ciphertext_name);

    const data = "this is a plain text.";
    entry.ciphertext_data = try allocator.alloc(u8, data.len);
    defer allocator.free(entry.ciphertext_data);

    encrypt(entry, derived_key, &vault_id, name, data);

    var decrypted_name: [name.len]u8 = undefined;
    var decrypted_data: [data.len]u8 = undefined;

    try decrypt(entry, derived_key, &vault_id, &decrypted_name, &decrypted_data);

    try expectEqualSlices(u8, data, &decrypted_data);
    try expectEqualSlices(u8, name, &decrypted_name);

    // The same ciphertext under a different entry id must not decrypt.
    entry.id[0] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        decrypt(entry, derived_key, &vault_id, &decrypted_name, &decrypted_data),
    );
}
