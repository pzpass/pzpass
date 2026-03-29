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

    header: Header,
    entries: std.ArrayList(Entry),

    pub fn init(allocator: std.mem.Allocator) !*Vault {
        var self = try allocator.create(Vault);

        self.entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, 0);

        self.fromFile(allocator) catch try self.new();
        return self;
    }

    fn new(self: *Vault) !void {
        var salt: [v1.SALT_LEN]u8 = undefined;
        std.crypto.random.bytes(&salt);

        self.header = .{
            .magic = config.MAGIC,
            .version = config.VERSION,
            .salt = salt,
            .iterations = v1.ITERATIONS,
            .mem_cost = v1.MEM_COST,
            .parallelism = v1.PARALLELISM,
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
        key: [v1.KEY_LEN]u8,
        out: *std.io.Writer,
    ) !void {
        for (self.entries.items) |item| {
            const name: []u8 = try allocator.alloc(u8, item.ciphertext_name.len);
            try pzcrypt.mlockSlice(name);
            defer {
                pzcrypt.zeroAndMunlock(name);
                allocator.free(name);
            }

            const data: []u8 = try allocator.alloc(u8, item.ciphertext_name.len);
            try pzcrypt.mlockSlice(data);
            defer {
                pzcrypt.zeroAndMunlock(data);
                allocator.free(data);
            }

            try pzcrypt.decrypt(&item, key, name, data);
            try out.print("{d: >5}: {x}\n", .{ item.id, name });
        }
        try out.writeAll(
            \\
        );
        try out.flush();
    }
};

test "init" {
    const allocator = std.testing.allocator;

    var vault = try Vault.init(allocator);
    defer vault.deinit(allocator);
}
