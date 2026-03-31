const std = @import("std");
const config = @import("config.zig");
const v1 = config.v1;
const storage = @import("storage.zig");
const format = @import("format.zig");
const pzcrypt = @import("crypto.zig");

pub const Vault = struct {
    pub const Header = struct {
        magic: [config.MAGIC.len]u8,
        version: usize,
        iterations: usize,
        mem_cost: u32,
        parallelism: usize,
        salt: [v1.SALT_LEN]u8,
        kek_ciphertext: [v1.KEY_LEN]u8,
        kek_nonce: [v1.NONCE_LEN]u8,
        kek_tag: [v1.TAG_LEN]u8,
    };

    pub const Entry = struct {
        id: usize,
        nonce_name: [v1.NONCE_LEN]u8,
        nonce_data: [v1.NONCE_LEN]u8,
        tag_name: [v1.TAG_LEN]u8,
        tag_data: [v1.TAG_LEN]u8,
        ciphertext_name: []u8,
        ciphertext_data: []u8,
    };

    vault_key: [v1.KEY_LEN]u8,
    entries: std.ArrayList(Entry),
    header: Header,

    pub fn init(allocator: std.mem.Allocator, password: []const u8) !*Vault {
        var self = try allocator.create(Vault);

        self.entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, 0);

        self.fromFile(allocator) catch try self.new(allocator, password);

        var kek = try pzcrypt.deriveKey(allocator, password, &self.header.salt);
        try pzcrypt.mlockSlice(&kek);
        defer pzcrypt.zeroAndMunlock(&kek);

        try pzcrypt.mlockSlice(&self.vault_key);

        const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
        try aead.decrypt(
            &self.vault_key,
            &self.header.kek_ciphertext,
            self.header.kek_tag,
            "",
            self.header.kek_nonce,
            kek,
        );

        if (std.mem.eql(u8, &kek, &self.vault_key)) {
            return error.KekIsVaultKey;
        }

        return self;
    }

    fn new(
        self: *Vault,
        allocator: std.mem.Allocator,
        password: []const u8,
    ) !void {
        std.crypto.random.bytes(&self.vault_key);
        try pzcrypt.mlockSlice(&self.vault_key);

        var salt: [v1.SALT_LEN]u8 = undefined;
        std.crypto.random.bytes(&salt);

        var nonce: [v1.NONCE_LEN]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        var tag: [v1.TAG_LEN]u8 = undefined;

        var password_key = try pzcrypt.deriveKey(allocator, password, &salt);
        try pzcrypt.mlockSlice(&password_key);
        defer pzcrypt.zeroAndMunlock(&password_key);

        var kek_ciphertext: [v1.KEY_LEN]u8 = undefined;
        const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
        aead.encrypt(
            &kek_ciphertext,
            &tag,
            &self.vault_key,
            "",
            nonce,
            password_key,
        );

        self.header = .{
            .magic = config.MAGIC,
            .version = config.VERSION,
            .salt = salt,
            .iterations = v1.ITERATIONS,
            .mem_cost = v1.MEM_COST,
            .parallelism = v1.PARALLELISM,
            .kek_nonce = nonce,
            .kek_ciphertext = kek_ciphertext,
            .kek_tag = tag,
        };
    }

    fn fromFile(self: *Vault, allocator: std.mem.Allocator) !void {
        const file_path = try storage.VaultPath.default(allocator, null);
        defer allocator.free(file_path);

        const data_from_file = try storage.readFileAlloc(allocator, file_path);
        defer allocator.free(data_from_file);

        try format.deserializeVault(allocator, self, data_from_file);
    }

    pub fn deinit(self: *Vault, allocator: std.mem.Allocator) void {
        pzcrypt.zeroAndMunlock(&self.vault_key);
        for (self.entries.items) |item| {
            allocator.free(item.ciphertext_name);
            allocator.free(item.ciphertext_data);
        }
        self.entries.deinit(allocator);
        allocator.destroy(self);
    }

    pub fn help(out: *std.io.Writer) !void {
        try out.writeAll(
            \\
            \\Press 'a' to add an entry,
            \\      'l' to list entries,
            \\      'i' to show the vault info,
            \\      'q' to quit the app,
            \\      'h' to see this help
            \\
            \\
        );
        try out.flush();
    }

    pub fn listEntries(
        self: *Vault,
        allocator: std.mem.Allocator,
        out: *std.io.Writer,
    ) !void {
        for (self.entries.items) |item| {
            const name: []u8 = try allocator.alloc(u8, item.ciphertext_name.len);
            try pzcrypt.mlockSlice(name);
            defer {
                pzcrypt.zeroAndMunlock(name);
                allocator.free(name);
            }

            const data: []u8 = try allocator.alloc(u8, item.ciphertext_data.len);
            try pzcrypt.mlockSlice(data);
            defer {
                pzcrypt.zeroAndMunlock(data);
                allocator.free(data);
            }

            try pzcrypt.decrypt(&item, self.vault_key, name, data);
            try out.print("{d: >5}: {x}\n", .{ item.id, name });
        }
        try out.writeAll(
            \\
        );
        try out.flush();
    }

    pub fn addEntry(
        self: *Vault,
        allocator: std.mem.Allocator,
        name: []const u8,
        data: []const u8,
    ) !void {
        const nonce_name = try allocator.alloc(u8, v1.NONCE_LEN);
        defer allocator.free(nonce_name);

        const nonce_data = try allocator.alloc(u8, v1.NONCE_LEN);
        defer allocator.free(nonce_data);

        const tag_name = try allocator.alloc(u8, v1.TAG_LEN);
        defer allocator.free(tag_name);

        const tag_data = try allocator.alloc(u8, v1.TAG_LEN);
        defer allocator.free(tag_data);

        std.crypto.random.bytes(nonce_name);
        std.crypto.random.bytes(nonce_data);

        std.crypto.random.bytes(tag_name);
        std.crypto.random.bytes(tag_data);

        const ciphertext_name = try allocator.alloc(u8, name.len);

        const ciphertext_data = try allocator.alloc(u8, data.len);

        var entry: Vault.Entry = .{
            .id = self.entries.items.len,
            .nonce_name = nonce_name[0..v1.NONCE_LEN].*,
            .nonce_data = nonce_data[0..v1.NONCE_LEN].*,
            .ciphertext_name = ciphertext_name,
            .ciphertext_data = ciphertext_data,
            .tag_name = tag_name[0..v1.TAG_LEN].*,
            .tag_data = tag_data[0..v1.TAG_LEN].*,
        };

        pzcrypt.encrypt(&entry, self.vault_key, name, data);

        try self.entries.append(allocator, entry);
    }
};

test "init" {
    const allocator = std.testing.allocator;

    var salt: [v1.SALT_LEN]u8 = undefined;
    std.crypto.random.bytes(&salt);

    var vault = try Vault.init(allocator, "blue-penguin");
    defer vault.deinit(allocator);

    //var out_buff: [4096]u8 = undefined;
    //var stdout = std.fs.File.stdout().writer(&out_buff);
    //const out = &stdout.interface;

    // try vault.listEntries(allocator, out);
}
