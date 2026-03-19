const std = @import("std");
const config = @import("config.zig");
const format = @import("format.zig");
const storage = @import("storage.zig");

pub const Vault = struct {
    pub const Header = struct {
        magic: [config.MAGIC.len]u8,
        version: usize,
        iterations: usize,
        mem_cost: u32,
        parallelism: usize,
        salt: [config.SALT_LEN]u8,
        entry_count: usize,
    };

    pub const Entry = struct {
        id: u64,
        len: usize,
        nonce: []u8,
        ciphertext: []u8,
        tag: []u8,
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
        var salt: [config.SALT_LEN]u8 = undefined;
        std.crypto.random.bytes(&salt);

        self.header = .{
            .magic = config.MAGIC,
            .version = config.VERSION,
            .salt = salt,
            .iterations = config.ITERATIONS,
            .mem_cost = config.MEM_COST,
            .parallelism = config.PARALLELISM,
            .entry_count = self.entries.items.len,
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
            allocator.free(item.nonce);
            allocator.free(item.ciphertext);
            allocator.free(item.tag);
        }
        self.entries.deinit(allocator);
        allocator.destroy(self);
    }
};

test "init" {
    const allocator = std.testing.allocator;

    var vault = try Vault.init(allocator);
    defer vault.deinit(allocator);
}
