const std = @import("std");

const MAGIC = @import("config.zig").MAGIC;
const Config = @import("config.zig").Config;
const storage = @import("storage.zig");
const format = @import("format.zig");
const pzcrypt = @import("crypto.zig");

const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Reader = std.io.Reader;
const Writer = std.io.Writer;
const Allocator = std.mem.Allocator;

const pass = @import("passwordgen.zig");
const dice = @import("dicephrase.zig");

pub const Vault = struct {
    pub const ENTRY_LEN = Config.ENTRY_LEN;

    pub const Header = struct {
        magic: [MAGIC.len]u8,
        version: usize,
        iterations: usize,
        mem_cost: u32,
        parallelism: usize,
        salt: [Config.SALT_LEN]u8,
        kek_ciphertext: [Config.KEY_LEN]u8,
        kek_nonce: [Config.NONCE_LEN]u8,
        kek_tag: [Config.TAG_LEN]u8,
    };

    pub const Entry = struct {
        nonce_name: [Config.NONCE_LEN]u8,
        nonce_data: [Config.NONCE_LEN]u8,
        tag_name: [Config.TAG_LEN]u8,
        tag_data: [Config.TAG_LEN]u8,
        ciphertext_name: []u8,
        ciphertext_data: []u8,

        pub fn init(
            n_name: []const u8,
            n_data: []const u8,
            t_name: []const u8,
            t_data: []const u8,
            c_name: []u8,
            c_data: []u8,
        ) Entry {
            return .{
                .nonce_name = n_name[0..Config.NONCE_LEN].*,
                .nonce_data = n_data[0..Config.NONCE_LEN].*,
                .tag_name = t_name[0..Config.TAG_LEN].*,
                .tag_data = t_data[0..Config.TAG_LEN].*,
                .ciphertext_name = c_name,
                .ciphertext_data = c_data,
            };
        }
    };

    vault_key: [Config.KEY_LEN]u8,
    entries: std.ArrayList(Entry),
    header: Header,
    file_path: []u8,

    pub fn init(allocator: Allocator, password: []const u8) !*Vault {
        var self = try allocator.create(Vault);
        self.entries = try std.ArrayList(Vault.Entry).initCapacity(allocator, 0);

        self.fromFile(allocator) catch try self.new(allocator, password);

        const password_key = try pzcrypt.deriveKey(allocator, password, &self.header.salt);
        try pzcrypt.mlockSlice(@constCast(&password_key));
        defer pzcrypt.zeroAndMunlock(&password_key);

        try pzcrypt.mlockSlice(&self.vault_key);

        aead.decrypt(
            &self.vault_key,
            &self.header.kek_ciphertext,
            self.header.kek_tag,
            "",
            self.header.kek_nonce,
            password_key,
        ) catch |err| {
            self.deinit(allocator);
            return err;
        };

        if (std.mem.eql(u8, &password_key, &self.vault_key)) {
            return error.KekIsVaultKey;
        }

        return self;
    }

    fn new(self: *Vault, allocator: Allocator, password: []const u8) !void {
        std.crypto.random.bytes(&self.vault_key);
        try pzcrypt.mlockSlice(&self.vault_key);

        self.header = .{
            .magic = MAGIC,
            .version = Config.VERSION,
            .salt = undefined,
            .iterations = Config.ITERATIONS,
            .mem_cost = Config.MEM_COST,
            .parallelism = Config.PARALLELISM,
            .kek_nonce = undefined,
            .kek_ciphertext = undefined,
            .kek_tag = undefined,
        };

        std.crypto.random.bytes(&self.header.salt);
        std.crypto.random.bytes(&self.header.kek_nonce);

        const password_key = try pzcrypt.deriveKey(allocator, password, &self.header.salt);
        try pzcrypt.mlockSlice(@constCast(&password_key));
        defer pzcrypt.zeroAndMunlock(&password_key);

        aead.encrypt(
            &self.header.kek_ciphertext,
            &self.header.kek_tag,
            &self.vault_key,
            "",
            self.header.kek_nonce,
            password_key,
        );
    }

    fn fromFile(self: *Vault, allocator: Allocator) !void {
        const is_test = @import("builtin").is_test;
        const file_path = if (is_test)
            try storage.VaultPath.testing(allocator, null)
        else
            try storage.VaultPath.default(allocator, null);
        defer allocator.free(file_path);

        self.file_path = file_path;

        const data_from_file = try storage.readFileAlloc(allocator, self.file_path);
        defer allocator.free(data_from_file);

        try format.deserializeVault(allocator, self, data_from_file);
    }

    pub fn deinit(self: *Vault, allocator: Allocator) void {
        pzcrypt.zeroAndMunlock(&self.vault_key);
        for (self.entries.items) |item| {
            allocator.free(item.ciphertext_name);
            allocator.free(item.ciphertext_data);
        }
        self.entries.deinit(allocator);
        allocator.destroy(self);
    }

    pub fn help(out: *Writer) !void {
        try out.writeAll(
            \\
            \\Press 'a' add an entry
            \\      'g' generate an entry
            \\      'l' list entries
            \\      'f' find entries
            \\      'o' open an entry
            \\      'i' show the vault info
            \\      's' save the vault
            \\      'u' update vault password
            \\      'q' quit the app
            \\      'h' see this help
            \\
            \\
        );
        try out.flush();
    }

    pub fn info(self: *Vault, out: *Writer) !void {
        try out.writeAll("\x1b[33m-----\x1b[0m\n");
        try out.print("Entries count: {d}\n", .{self.entries.items.len});
        try out.print("Vault stored as:\n{s}\n", .{self.file_path});
        try out.flush();
    }

    pub fn short_help(out: *Writer) !void {
        try out.writeAll("\x1b[33m-----\x1b[0m\n");
        try out.writeAll("a - add, g - generate, d - delete, f - find, l - list, o - open, h - more commands\n");
        try out.flush();
    }

    pub fn listEntries(
        self: *Vault,
        allocator: Allocator,
        out: *Writer,
        filter: ?[]const u8,
    ) !void {
        try out.writeAll("\x1b[33m-----\x1b[0m\n");
        for (self.entries.items, 0..) |item, index| {
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
            if (filter) |actual_filter| {
                if (std.mem.containsAtLeast(u8, name, 1, actual_filter))
                    try out.print("{d: >5}: {s}\n", .{ index, name });
            } else {
                try out.print("{d: >5}: {s}\n", .{ index, name });
            }
        }
        if (self.entries.items.len == 0) {
            try out.writeAll("\x1b[33mVault has no entries.\x1b[0m\n");
        }
        try out.flush();
    }

    pub fn addEntry(
        self: *Vault,
        allocator: Allocator,
        name: []const u8,
        data: []const u8,
    ) !void {
        const nonce_name = try allocator.alloc(u8, Config.NONCE_LEN);
        defer allocator.free(nonce_name);

        const nonce_data = try allocator.alloc(u8, Config.NONCE_LEN);
        defer allocator.free(nonce_data);

        const tag_name = try allocator.alloc(u8, Config.TAG_LEN);
        defer allocator.free(tag_name);

        const tag_data = try allocator.alloc(u8, Config.TAG_LEN);
        defer allocator.free(tag_data);

        std.crypto.random.bytes(nonce_name);
        std.crypto.random.bytes(nonce_data);

        const ciphertext_name = try allocator.alloc(u8, name.len);
        const ciphertext_data = try allocator.alloc(u8, data.len);

        var entry = Vault.Entry.init(
            nonce_name,
            nonce_data,
            tag_name,
            tag_data,
            ciphertext_name,
            ciphertext_data,
        );

        pzcrypt.encrypt(&entry, self.vault_key, name, data);

        try self.entries.append(allocator, entry);
    }

    pub fn addEntryPrompt(
        self: *Vault,
        allocator: Allocator,
        out: *Writer,
        in: *Reader,
    ) !void {
        const name: []u8 = getInput(
            allocator,
            out,
            in,
            "\x1b[33mNew entry name:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return,
            else => return err,
        };
        defer allocator.free(name);

        const data: []u8 = getInput(
            allocator,
            out,
            in,
            "\x1b[33mNew entry data:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return,
            else => return err,
        };
        defer allocator.free(data);

        try self.addEntry(allocator, name, data);

        try out.writeAll("\x1b[33mEntry added successfully.\x1b[0m\n");
        try out.flush();

        std.crypto.secureZero(u8, @constCast(name));
        std.crypto.secureZero(u8, @constCast(data));
    }

    pub fn addPasswordPrompt(
        self: *Vault,
        allocator: Allocator,
        out: *Writer,
        in: *Reader,
    ) !void {
        const name: []u8 = getInput(
            allocator,
            out,
            in,
            "\x1b[33mNew entry name:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return,
            else => return err,
        };
        defer allocator.free(name);

        const option: []u8 = getInput(
            allocator,
            out,
            in,
            "\x1b[33mPut \x1b[0mdice\x1b[33m or \x1b[0mpass\x1b[33m :\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return,
            else => return err,
        };
        defer allocator.free(option);

        if (std.mem.eql(u8, "dice", option) or std.mem.eql(u8, "pass", option)) {} else {
            try out.writeAll("\x1b[33mOnly valid options are \x1b[0mdice\x1b[33m or \x1b[0mpass\x1b[33m :\x1b[0m\n");
            try out.flush();
            return;
        }

        const length = getInputNumeric(
            out,
            in,
            "\x1b[33mLength:\x1b[0m ",
        ) catch |err| switch (err) {
            error.WrongInput => return,
            else => return err,
        };

        const data = if (std.mem.eql(u8, option, "dice"))
            try dice.generateDicePhrase(allocator, length)
        else
            try pass.generate(allocator, length);
        defer allocator.free(data);

        try self.addEntry(allocator, name, data);

        try out.writeAll("\x1b[33mEntry added successfully.\x1b[0m\n");
        try out.flush();

        std.crypto.secureZero(u8, @constCast(name));
        std.crypto.secureZero(u8, @constCast(data));
    }

    pub fn findEntryPrompt(
        self: *Vault,
        allocator: Allocator,
        out: *Writer,
        in: *Reader,
    ) !void {
        const name: []u8 = getInput(
            allocator,
            out,
            in,
            "\x1b[33mFind:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return,
            else => return err,
        };
        defer allocator.free(name);

        try self.listEntries(allocator, out, name);

        std.crypto.secureZero(u8, @constCast(name));
    }

    pub fn openEntryPrompt(
        self: *Vault,
        allocator: Allocator,
        out: *Writer,
        in: *Reader,
    ) !void {
        const index = getInputNumeric(
            out,
            in,
            "\x1b[33mOpen item index:\x1b[0m ",
        ) catch |err| switch (err) {
            error.WrongInput => return,
            else => return err,
        };

        if (index < 0 or index >= self.entries.items.len) {
            try out.writeAll("\x1b[33mIndex is out of bounds.\x1b[0m\n");
            try out.flush();
            return;
        }

        const item = self.entries.items[index];

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
        try out.print("\x1b[33mName:\x1b[0m {s}\n\x1b[33mData:\x1b[0m {s}\n", .{ name, data });
        try out.flush();
    }

    pub fn deleteEntry(
        self: *Vault,
        allocator: Allocator,
        index: usize,
    ) !void {
        if (index < 0 or index >= self.entries.items.len) {
            return error.OutOfBounbds;
        }
        const entry = self.entries.orderedRemove(index);
        allocator.free(entry.ciphertext_name);
        allocator.free(entry.ciphertext_data);
    }

    pub fn deleteEntryPrompt(
        self: *Vault,
        allocator: Allocator,
        out: *Writer,
        in: *Reader,
    ) !void {
        const index = getInputNumeric(
            out,
            in,
            "\x1b[33mDelete item index:\x1b[0m ",
        ) catch |err| switch (err) {
            error.WrongInput => return printWrongInput(out),
            else => return err,
        };

        if (index < 0 or index >= self.entries.items.len) {
            return printOutOfBounds(out);
        }

        self.deleteEntry(allocator, index) catch |err| switch (err) {
            error.OutOfBounbds => return printOutOfBounds(out),
            else => return err,
        };
        try out.print("\x1b[33mEntry {d} deleted successfully.\x1b[0m\n", .{index});
        try out.flush();
    }

    pub fn save(
        self: *Vault,
        allocator: Allocator,
    ) !void {
        const vault_serialized = try format.serializeVault(allocator, self);
        defer allocator.free(vault_serialized);

        try storage.writeFile(self.file_path, vault_serialized);
    }

    pub fn updatePassword(
        self: *Vault,
        allocator: Allocator,
        password: []const u8,
    ) !void {
        const password_key = try pzcrypt.deriveKey(allocator, password, &self.header.salt);
        try pzcrypt.mlockSlice(@constCast(&password_key));
        defer pzcrypt.zeroAndMunlock(&password_key);

        aead.encrypt(
            &self.header.kek_ciphertext,
            &self.header.kek_tag,
            &self.vault_key,
            "",
            self.header.kek_nonce,
            password_key,
        );
    }

    pub fn updatePasswordPrompt(
        self: *Vault,
        allocator: Allocator,
        out: *Writer,
        in: *Reader,
    ) !void {
        const password: []u8 = getInput(
            allocator,
            out,
            in,
            "\x1b[33mEnter new password:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return,
            else => return err,
        };
        defer allocator.free(password);

        try out.writeAll("\n");
        try out.flush();

        const password_confirmation: []u8 = getInput(
            allocator,
            out,
            in,
            "\x1b[33mConfirm new password:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return,
            else => return err,
        };
        defer allocator.free(password_confirmation);

        try out.writeAll("\n");
        try out.flush();

        if (std.mem.eql(u8, password, password_confirmation)) {
            try self.updatePassword(allocator, password);
        }

        try out.writeAll("\x1b[33mPassword successfully updated.\x1b[0m\n");
        try out.flush();

        std.crypto.secureZero(u8, @constCast(password));
        std.crypto.secureZero(u8, @constCast(password_confirmation));
    }
};

pub fn takeDelimiter(
    out: *Writer,
    in: *Reader,
    delimeter: u8,
) !?[]u8 {
    const slice = in.takeDelimiter(delimeter) catch |err| switch (err) {
        error.StreamTooLong => {
            try printInputTooLong(out, in.bufferedLen());
            _ = try in.discardDelimiterInclusive('\n');
            return err;
        },
        else => return err,
    };
    return slice;
}

pub fn flushInput(
    out: *Writer,
    in: *Reader,
) !void {
    while (true) {
        if (in.bufferedLen() == 0) break else {
            _ = try takeDelimiter(out, in, '\n');
        }
    }
}

fn getInput(
    allocator: Allocator,
    out: *Writer,
    in: *Reader,
    prompt: []const u8,
) ![]u8 {
    while (true) {
        try out.writeAll(prompt);
        try out.flush();
        const input_string_slice = (try takeDelimiter(out, in, '\n')) orelse continue;
        const input_string_trimmed = std.mem.trim(u8, input_string_slice, " \r\t");
        if (input_string_trimmed.len == 0) return error.EmptyString;
        const input_string = try allocator.dupe(u8, input_string_trimmed);
        try flushInput(out, in);
        try out.flush();
        return input_string;
    }
}

fn getInputNumeric(
    out: *Writer,
    in: *Reader,
    prompt: []const u8,
) !usize {
    try out.writeAll(prompt);
    try out.flush();

    const index_slice_option = try in.takeDelimiter('\n');
    const index_slice = index_slice_option orelse return error.WrongInput;

    const index = std.fmt.parseInt(usize, index_slice, 10) catch error.WrongInput;

    try out.writeAll("\n");
    try out.flush();
    return index;
}

fn printWrongInput(out: *Writer) !void {
    try out.writeAll("\x1b[31mWrong input. Use entry index.\x1b[0m\n");
    try out.flush();
    return;
}

fn printInputTooLong(out: *Writer, length: usize) !void {
    try out.print("\x1b[31mInput is too long. Max length is {d}.\x1b[0m\n", .{length});
    try out.flush();
    return;
}

fn printOutOfBounds(out: *Writer) !void {
    try out.writeAll("\x1b[31mIndex is out of bounds.\x1b[0m\n");
    try out.flush();
    return;
}

test "init" {
    const allocator = std.testing.allocator;

    var vault = try Vault.init(allocator, "blue-penguin");
    defer vault.deinit(allocator);

    try vault.addEntry(allocator, "test", "test data");
    try vault.deleteEntry(allocator, 0);

    try vault.updatePassword(allocator, "orange-tiger");
}
