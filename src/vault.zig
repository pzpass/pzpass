const std = @import("std");
const config = @import("config.zig");

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
        nonce: [config.NONCE_LEN]u8,
        ciphertext: []const u8,
    };

    header: Header,
    entries: std.ArrayList(Entry),
};
