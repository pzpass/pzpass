const std = @import("std");

const MAGIC = @import("config.zig").MAGIC;
const Config = @import("config.zig").Config;
const storage = @import("storage.zig");
const format = @import("format.zig");
const pzcrypt = @import("crypto.zig");

const aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;
const Allocator = std.mem.Allocator;
const Key = pzcrypt.Key;

const pass = @import("passwordgen.zig");
const dice = @import("dicephrase.zig");

pub const Vault = struct {
    pub const Options = struct {
        out: *Writer,
        in: *Reader,
    };

    pub const ENTRY_LEN = Config.ENTRY_LEN;

    pub const Header = struct {
        magic: [MAGIC.len]u8,
        version: usize,
        iterations: u32,
        mem_cost: u32,
        parallelism: u32,
        salt: [Config.SALT_LEN]u8,
        kek_ciphertext: [Config.KEY_LEN]u8,
        kek_nonce: [Config.NONCE_LEN]u8,
        kek_tag: [Config.TAG_LEN]u8,
        /// v3+: random, fixed for the vault's lifetime; part of every entry's
        /// associated data. Zero for v1/v2 files.
        vault_id: [Config.ID_LEN]u8,
    };

    pub const Entry = struct {
        /// v3+: random per entry; part of the entry's associated data.
        /// Zero for entries read from v1/v2 files.
        id: [Config.ID_LEN]u8,
        nonce_name: [Config.NONCE_LEN]u8,
        nonce_data: [Config.NONCE_LEN]u8,
        tag_name: [Config.TAG_LEN]u8,
        tag_data: [Config.TAG_LEN]u8,
        ciphertext_name: []u8,
        ciphertext_data: []u8,
    };

    /// Points into `vault_key_page`, a page of its own that is mlocked and
    /// wiped on `deinit`.
    vault_key: *Key,
    vault_key_page: pzcrypt.Secret,
    entries: std.ArrayList(Entry),
    header: Header,
    file_path: []u8,
    /// A v1/v2 file was upgraded to the current format in memory; it is
    /// written in the new format on the next save.
    migrated: bool,
    /// The vault key was rotated, so the `.bak` written by the next save
    /// (still readable with the old password) must be deleted.
    purge_backup: bool,

    /// An empty vault with a locked (but unset) key and no header. Takes
    /// ownership of `file_path`, also on error. Release with `deinit`.
    pub fn createEmpty(allocator: Allocator, file_path: []u8) !*Vault {
        errdefer allocator.free(file_path);
        const self = try allocator.create(Vault);
        errdefer allocator.destroy(self);
        const key_page = try pzcrypt.allocKey(allocator);
        self.* = .{
            .vault_key = key_page[0..Config.KEY_LEN],
            .vault_key_page = key_page,
            .entries = .empty,
            .header = undefined,
            .file_path = file_path,
            .migrated = false,
            .purge_backup = false,
        };
        return self;
    }

    pub fn init(
        allocator: Allocator,
        io: std.Io,
        password: []const u8,
        base_dir: []const u8,
        sub_dir: []const u8,
        file_name: []const u8,
    ) !*Vault {
        const file_path = try allocator.print("{s}/{s}/{s}", .{ base_dir, sub_dir, file_name });
        const self = try createEmpty(allocator, file_path);
        errdefer self.deinit(allocator);

        const bytes = storage.readFileAlloc(allocator, io, base_dir, sub_dir, file_name) catch |err| switch (err) {
            error.FileNotFound => {
                // `new` generates and wraps the key itself; no second Argon2 run.
                try self.new(allocator, io, password);
                return self;
            },
            else => return err,
        };
        defer allocator.free(bytes);

        try format.deserializeVault(allocator, self, bytes);

        const password_key_page = try pzcrypt.allocKey(allocator);
        defer pzcrypt.freeSecret(allocator, password_key_page);
        const password_key = password_key_page[0..Config.KEY_LEN];
        try pzcrypt.deriveKey(
            allocator,
            io,
            password_key,
            password,
            &self.header.salt,
            self.header.iterations,
            self.header.mem_cost,
            self.header.parallelism,
        );

        var aad_buf: [header_aad_max_len]u8 = undefined;
        try aead.decrypt(
            self.vault_key,
            &self.header.kek_ciphertext,
            self.header.kek_tag,
            headerAad(&self.header, &aad_buf),
            self.header.kek_nonce,
            password_key.*,
        );

        if (std.mem.eql(u8, password_key, self.vault_key)) {
            return error.KekIsVaultKey;
        }

        if (self.header.version >= 3) {
            try format.verifyMac(self.vault_key, bytes);
        } else {
            try self.migrate(allocator, io, password_key);
        }

        return self;
    }

    /// Upgrades a v1/v2 vault to the current format in memory: assigns vault and
    /// entry ids, re-encrypts every entry with them as associated data, and
    /// re-wraps the vault key with the new header. The data key is unchanged.
    fn migrate(
        self: *Vault,
        allocator: Allocator,
        io: std.Io,
        password_key: *const Key,
    ) !void {
        const rng_impl: std.Random.IoSource = .{ .io = io };
        const rng = rng_impl.interface();

        var vault_id: [Config.ID_LEN]u8 = undefined;
        rng.bytes(&vault_id);

        for (self.entries.items) |*entry| {
            const name = try pzcrypt.allocSecret(allocator, entry.ciphertext_name.len);
            defer pzcrypt.freeSecret(allocator, name);
            const data = try pzcrypt.allocSecret(allocator, entry.ciphertext_data.len);
            defer pzcrypt.freeSecret(allocator, data);

            try pzcrypt.decrypt(entry, self.vault_key, null, name, data);

            // Same lengths, so the ciphertext buffers are reused; nonces are fresh.
            rng.bytes(&entry.id);
            rng.bytes(&entry.nonce_name);
            rng.bytes(&entry.nonce_data);
            pzcrypt.encrypt(entry, self.vault_key, &vault_id, name, data);
        }

        self.header.vault_id = vault_id;
        self.header.version = Config.VERSION;
        self.wrapKey(io, password_key);
        self.migrated = true;
    }

    /// Encrypts the vault key under `password_key` with a fresh nonce,
    /// authenticating the current header.
    fn wrapKey(self: *Vault, io: std.Io, password_key: *const Key) void {
        const rng_impl: std.Random.IoSource = .{ .io = io };
        rng_impl.interface().bytes(&self.header.kek_nonce);

        var aad_buf: [header_aad_max_len]u8 = undefined;
        aead.encrypt(
            &self.header.kek_ciphertext,
            &self.header.kek_tag,
            self.vault_key,
            headerAad(&self.header, &aad_buf),
            self.header.kek_nonce,
            password_key.*,
        );
    }

    /// Decrypts an entry of this vault into caller-provided buffers sized
    /// like its ciphertexts (normally from `pzcrypt.allocSecret`).
    pub fn decryptEntry(self: *const Vault, entry: *const Entry, name: []u8, data: []u8) !void {
        const vault_id: ?*const [Config.ID_LEN]u8 =
            if (self.header.version >= 3) &self.header.vault_id else null;
        try pzcrypt.decrypt(entry, self.vault_key, vault_id, name, data);
    }

    /// An entry's plaintext, each field in its own locked page.
    pub const Plaintext = struct {
        name: pzcrypt.Secret,
        data: pzcrypt.Secret,

        pub fn deinit(self: Plaintext, allocator: Allocator) void {
            pzcrypt.freeSecret(allocator, self.name);
            pzcrypt.freeSecret(allocator, self.data);
        }
    };

    /// Decrypts an entry into locked memory. Release with `Plaintext.deinit`.
    pub fn decryptEntryAlloc(self: *const Vault, allocator: Allocator, entry: *const Entry) !Plaintext {
        const name = try pzcrypt.allocSecret(allocator, entry.ciphertext_name.len);
        errdefer pzcrypt.freeSecret(allocator, name);
        const data = try pzcrypt.allocSecret(allocator, entry.ciphertext_data.len);
        errdefer pzcrypt.freeSecret(allocator, data);
        try self.decryptEntry(entry, name, data);
        return .{ .name = name, .data = data };
    }

    /// Decrypts only an entry's name (for listing and matching), leaving the
    /// secret data encrypted. Release with `pzcrypt.freeSecret`.
    pub fn decryptNameAlloc(self: *const Vault, allocator: Allocator, entry: *const Entry) !pzcrypt.Secret {
        const vault_id: ?*const [Config.ID_LEN]u8 =
            if (self.header.version >= 3) &self.header.vault_id else null;
        const name = try pzcrypt.allocSecret(allocator, entry.ciphertext_name.len);
        errdefer pzcrypt.freeSecret(allocator, name);
        try pzcrypt.decryptName(entry, self.vault_key, vault_id, name);
        return name;
    }

    fn new(
        self: *Vault,
        allocator: Allocator,
        io: std.Io,
        password: []const u8,
    ) !void {
        const rng_impl: std.Random.IoSource = .{ .io = io };
        const rng = rng_impl.interface();
        rng.bytes(self.vault_key);

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
            .vault_id = undefined,
        };

        rng.bytes(&self.header.salt);
        rng.bytes(&self.header.vault_id);

        const password_key_page = try pzcrypt.allocKey(allocator);
        defer pzcrypt.freeSecret(allocator, password_key_page);
        const password_key = password_key_page[0..Config.KEY_LEN];
        try pzcrypt.deriveKey(
            allocator,
            io,
            password_key,
            password,
            &self.header.salt,
            self.header.iterations,
            self.header.mem_cost,
            self.header.parallelism,
        );

        self.wrapKey(io, password_key);
    }

    pub fn deinit(self: *Vault, allocator: Allocator) void {
        allocator.free(self.file_path);
        pzcrypt.freeSecret(allocator, self.vault_key_page);
        freeEntries(self, allocator);
        allocator.destroy(self);
    }

    pub fn help(out: *Writer) !void {
        try out.writeAll(
            \\
            \\Press 'a' add an entry
            \\      'g' generate an entry
            \\      'e' edit an entry
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
        try out.print("Argon: mem_cost {d}, iterations {d}\n", .{
            self.header.mem_cost,
            self.header.iterations,
        });
        try out.print("Vault stored as:\n{s}\n", .{self.file_path});
        try out.flush();
    }

    pub fn short_help(out: *Writer) !void {
        try out.writeAll("\x1b[33m-----\x1b[0m\n");
        try out.writeAll("a - add, g - generate, d - delete, f - find, e - edit, o - open, h - help\n");
        try out.flush();
    }

    pub fn listEntries(
        self: *Vault,
        allocator: Allocator,
        out: *Writer,
        filter: ?[]const u8,
    ) !void {
        try out.writeAll("\x1b[33m-----\x1b[0m\n");
        for (self.entries.items, 0..) |*item, index| {
            // Names only: listing never decrypts the secrets themselves.
            const name = try self.decryptNameAlloc(allocator, item);
            defer pzcrypt.freeSecret(allocator, name);

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
        io: std.Io,
        name: []const u8,
        data: []const u8,
    ) !void {
        const entry = try self.makeEntry(allocator, io, name, data);
        errdefer freeEntry(allocator, entry);

        try self.entries.append(allocator, entry);
    }

    /// Encrypts `name`/`data` into a new entry; the caller owns its ciphertexts.
    fn makeEntry(
        self: *Vault,
        allocator: Allocator,
        io: std.Io,
        name: []const u8,
        data: []const u8,
    ) !Entry {
        return encryptEntry(allocator, io, self.vault_key, &self.header.vault_id, name, data);
    }

    pub fn addEntryPrompt(
        self: *Vault,
        allocator: Allocator,
        io: std.Io,
        options: Options,
    ) !bool {
        const out = options.out;
        const in = options.in;
        const name = getInput(
            allocator,
            out,
            in,
            "\x1b[33mNew entry name:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return false,
            else => return err,
        };
        defer pzcrypt.freeSecret(allocator, name);

        const data = getInput(
            allocator,
            out,
            in,
            "\x1b[33mNew entry data:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return false,
            else => return err,
        };
        defer pzcrypt.freeSecret(allocator, data);

        try self.addEntry(allocator, io, name, data);

        try out.writeAll("\x1b[33mEntry added successfully.\x1b[0m\n");
        try out.flush();

        return true;
    }

    pub fn addPasswordPrompt(
        self: *Vault,
        allocator: Allocator,
        io: std.Io,
        options: Options,
    ) !bool {
        const out = options.out;
        const in = options.in;
        const name = getInput(
            allocator,
            out,
            in,
            "\x1b[33mNew entry name:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return false,
            else => return err,
        };
        defer pzcrypt.freeSecret(allocator, name);

        const option = getInput(
            allocator,
            out,
            in,
            "\x1b[33mPut \x1b[0mdice\x1b[33m or \x1b[0mpass\x1b[33m :\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return false,
            else => return err,
        };
        defer pzcrypt.freeSecret(allocator, option);

        if (std.mem.eql(u8, "dice", option) or std.mem.eql(u8, "pass", option)) {} else {
            try out.writeAll("\x1b[33mOnly valid options are \x1b[0mdice\x1b[33m or \x1b[0mpass\x1b[33m :\x1b[0m\n");
            try out.flush();
            return false;
        }

        const length = getInputNumeric(
            out,
            in,
            "\x1b[33mLength:\x1b[0m ",
        ) catch |err| switch (err) {
            error.WrongInput => return false,
            else => return err,
        };

        const data = if (std.mem.eql(u8, option, "dice"))
            try dice.generateDicePhrase(allocator, io, length)
        else
            try pass.generate(allocator, io, length);
        defer pzcrypt.freeSecret(allocator, data);

        try self.addEntry(allocator, io, name, data);

        try out.writeAll("\x1b[33mEntry added successfully.\x1b[0m\n");
        try out.flush();

        return true;
    }

    pub fn findEntryPrompt(
        self: *Vault,
        allocator: Allocator,
        options: Options,
    ) !void {
        const out = options.out;
        const in = options.in;
        const name = getInput(
            allocator,
            out,
            in,
            "\x1b[33mFind:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return,
            else => return err,
        };
        defer pzcrypt.freeSecret(allocator, name);

        try self.listEntries(allocator, out, name);
    }

    pub fn openEntryPrompt(
        self: *Vault,
        allocator: Allocator,
        options: Options,
    ) !void {
        const out = options.out;
        const in = options.in;
        const index = getInputNumeric(
            out,
            in,
            "\x1b[33mOpen item index:\x1b[0m ",
        ) catch |err| switch (err) {
            error.WrongInput => return printWrongInput(out),
            else => return err,
        };

        if (index >= self.entries.items.len) {
            try out.writeAll("\x1b[33mIndex is out of bounds.\x1b[0m\n");
            try out.flush();
            return;
        }

        const plain = try self.decryptEntryAlloc(allocator, &self.entries.items[index]);
        defer plain.deinit(allocator);

        try out.print("\x1b[33mName:\x1b[0m {s}\n\x1b[33mData:\x1b[0m {s}\n", .{ plain.name, plain.data });
        try out.flush();
    }

    pub fn editEntryPrompt(
        self: *Vault,
        allocator: Allocator,
        io: std.Io,
        options: Options,
    ) !bool {
        const out = options.out;
        const in = options.in;
        const index = getInputNumeric(
            out,
            in,
            "\x1b[33mItem index:\x1b[0m ",
        ) catch |err| switch (err) {
            error.WrongInput => return false,
            else => return err,
        };

        if (index >= self.entries.items.len) {
            try out.writeAll("\x1b[33mIndex is out of bounds.\x1b[0m\n");
            try out.flush();
            return false;
        }

        const current = try self.decryptEntryAlloc(allocator, &self.entries.items[index]);
        defer current.deinit(allocator);

        try out.print("\x1b[33mName:\x1b[0m {s}\n\x1b[33mData:\x1b[0m {s}\n", .{ current.name, current.data });
        try out.flush();

        // null = keep the current value.
        const new_name: ?pzcrypt.Secret = getInput(
            allocator,
            out,
            in,
            "\x1b[33mNew entry name (leave empty to keep):\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => null,
            else => return err,
        };
        defer if (new_name) |s| pzcrypt.freeSecret(allocator, s);

        const new_data: ?pzcrypt.Secret = getInput(
            allocator,
            out,
            in,
            "\x1b[33mNew entry data (leave empty to keep):\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => null,
            else => return err,
        };
        defer if (new_data) |s| pzcrypt.freeSecret(allocator, s);

        const updated_name: []const u8 = new_name orelse current.name;
        const updated_data: []const u8 = new_data orelse current.data;

        // Replace in place so the edited entry keeps its index.
        const updated = try self.makeEntry(allocator, io, updated_name, updated_data);
        const old = self.entries.items[index];
        self.entries.items[index] = updated;
        freeEntry(allocator, old);

        try out.writeAll("\x1b[33mEntry updated successfully.\x1b[0m\n");
        try out.flush();

        return true;
    }

    pub fn deleteEntry(
        self: *Vault,
        allocator: Allocator,
        index: usize,
    ) !void {
        if (index >= self.entries.items.len) {
            return error.OutOfBounds;
        }
        freeEntry(allocator, self.entries.orderedRemove(index));
    }

    pub fn deleteEntryPrompt(
        self: *Vault,
        allocator: Allocator,
        options: Options,
    ) !bool {
        const out = options.out;
        const in = options.in;
        const index = getInputNumeric(
            out,
            in,
            "\x1b[33mDelete item index:\x1b[0m ",
        ) catch |err| switch (err) {
            error.WrongInput => {
                try printWrongInput(out);
                return false;
            },
            else => return err,
        };

        if (index >= self.entries.items.len) {
            try printOutOfBounds(out);
            return false;
        }

        const name = getInput(
            allocator,
            out,
            in,
            "\x1b[33mEntry name:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return false,
            else => return err,
        };
        defer pzcrypt.freeSecret(allocator, name);

        const entry_name = try self.decryptNameAlloc(allocator, &self.entries.items[index]);
        defer pzcrypt.freeSecret(allocator, entry_name);

        if (std.mem.eql(u8, name, entry_name)) {
            self.deleteEntry(allocator, index) catch |err| switch (err) {
                error.OutOfBounds => {
                    try printOutOfBounds(out);
                    return false;
                },
            };
            try out.print("\x1b[33mEntry {d} deleted successfully.\x1b[0m\n", .{index});
            try out.flush();
            return true;
        } else {
            try out.writeAll("\x1b[33mName does not match.\x1b[0m\n");
            try out.flush();
            return false;
        }
    }

    pub fn save(
        self: *Vault,
        allocator: Allocator,
        io: std.Io,
        base_dir: []const u8,
        sub_dir: []const u8,
        file_name: []const u8,
    ) !void {
        const vault_serialized = try format.serializeVault(allocator, self);
        defer allocator.free(vault_serialized);

        try storage.writeFile(
            allocator,
            io,
            base_dir,
            sub_dir,
            file_name,
            vault_serialized,
        );

        if (self.purge_backup) {
            // The backup is the pre-rotation file, readable with the old password.
            const bak_name = try allocator.print("{s}.bak", .{file_name});
            defer allocator.free(bak_name);
            try storage.deleteFile(io, base_dir, sub_dir, bak_name);
            self.purge_backup = false;
        }
    }

    /// Changes the password and rotates the vault key: every entry is
    /// re-encrypted under a fresh key, so the old password together with an old
    /// copy of the file no longer opens newer versions of the vault. The vault
    /// is left unchanged if anything fails.
    pub fn updatePassword(
        self: *Vault,
        allocator: Allocator,
        io: std.Io,
        password: []const u8,
    ) !void {
        const rng_impl: std.Random.IoSource = .{ .io = io };
        const rng = rng_impl.interface();

        const new_key_page = try pzcrypt.allocKey(allocator);
        errdefer pzcrypt.freeSecret(allocator, new_key_page);
        const new_key = new_key_page[0..Config.KEY_LEN];
        rng.bytes(new_key);

        // Re-encrypt into new buffers so a failure leaves the vault as it was.
        var rotated = try std.ArrayList(Entry).initCapacity(allocator, self.entries.items.len);
        errdefer {
            for (rotated.items) |entry| freeEntry(allocator, entry);
            rotated.deinit(allocator);
        }
        for (self.entries.items) |*entry| {
            const plain = try self.decryptEntryAlloc(allocator, entry);
            defer plain.deinit(allocator);
            rotated.appendAssumeCapacity(
                try encryptEntry(allocator, io, new_key, &self.header.vault_id, plain.name, plain.data),
            );
        }

        var salt: [Config.SALT_LEN]u8 = undefined;
        rng.bytes(&salt);
        const password_key_page = try pzcrypt.allocKey(allocator);
        defer pzcrypt.freeSecret(allocator, password_key_page);
        const password_key = password_key_page[0..Config.KEY_LEN];
        try pzcrypt.deriveKey(
            allocator,
            io,
            password_key,
            password,
            &salt,
            Config.ITERATIONS,
            Config.MEM_COST,
            Config.PARALLELISM,
        );

        // Commit. Nothing below can fail.
        freeEntries(self, allocator);
        self.entries = rotated;
        pzcrypt.freeSecret(allocator, self.vault_key_page);
        self.vault_key_page = new_key_page;
        self.vault_key = new_key;
        self.header.salt = salt;
        self.header.iterations = Config.ITERATIONS;
        self.header.mem_cost = Config.MEM_COST;
        self.header.parallelism = Config.PARALLELISM;
        self.header.version = Config.VERSION;
        self.wrapKey(io, password_key);
        self.purge_backup = true;
    }

    pub fn updatePasswordPrompt(
        self: *Vault,
        allocator: Allocator,
        io: std.Io,
        options: Options,
    ) !bool {
        const out = options.out;
        const in = options.in;
        const password = getInput(
            allocator,
            out,
            in,
            "\x1b[33mEnter new password:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return false,
            else => return err,
        };
        defer pzcrypt.freeSecret(allocator, password);

        try out.writeAll("\n");
        try out.flush();

        const password_confirmation = getInput(
            allocator,
            out,
            in,
            "\x1b[33mConfirm new password:\x1b[0m ",
        ) catch |err| switch (err) {
            error.EmptyString => return false,
            else => return err,
        };
        defer pzcrypt.freeSecret(allocator, password_confirmation);

        try out.writeAll("\n");
        try out.flush();

        if (!std.mem.eql(u8, password, password_confirmation)) {
            return false;
        }
        try self.updatePassword(allocator, io, password);

        try out.writeAll("\x1b[33mPassword successfully updated. Save to keep it; saving also deletes the old backup.\x1b[0m\n");
        try out.flush();

        return true;
    }
};

fn freeEntry(allocator: Allocator, entry: Vault.Entry) void {
    allocator.free(entry.ciphertext_name);
    allocator.free(entry.ciphertext_data);
}

fn freeEntries(self: *Vault, allocator: Allocator) void {
    for (self.entries.items) |item| freeEntry(allocator, item);
    self.entries.deinit(allocator);
}

/// Encrypts `name`/`data` into a new entry with a fresh id and nonces; the
/// caller owns its ciphertexts.
fn encryptEntry(
    allocator: Allocator,
    io: std.Io,
    key: *const Key,
    vault_id: *const [Config.ID_LEN]u8,
    name: []const u8,
    data: []const u8,
) !Vault.Entry {
    const ciphertext_name = try allocator.alloc(u8, name.len);
    errdefer allocator.free(ciphertext_name);
    const ciphertext_data = try allocator.alloc(u8, data.len);

    var entry: Vault.Entry = .{
        .id = undefined,
        .nonce_name = undefined,
        .nonce_data = undefined,
        .tag_name = undefined,
        .tag_data = undefined,
        .ciphertext_name = ciphertext_name,
        .ciphertext_data = ciphertext_data,
    };

    const rng_impl: std.Random.IoSource = .{ .io = io };
    const rng = rng_impl.interface();
    rng.bytes(&entry.id);
    rng.bytes(&entry.nonce_name);
    rng.bytes(&entry.nonce_data);

    pzcrypt.encrypt(&entry, key, vault_id, name, data);
    return entry;
}

const header_aad_v2_len = @sizeOf(usize) + @sizeOf(u32) * 3 + Config.SALT_LEN;
const header_aad_max_len = header_aad_v2_len + Config.ID_LEN;

/// Associated data for wrapping the vault key. v1: none. v2: version, Argon2
/// parameters and salt. v3: v2 plus the vault id.
fn headerAad(header: *const Vault.Header, buf: *[header_aad_max_len]u8) []const u8 {
    if (header.version == 1) return buf[0..0];
    var offset: usize = 0;

    var size_buff: [@sizeOf(usize)]u8 = undefined;
    std.mem.writeInt(usize, &size_buff, header.version, .little);
    @memcpy(buf[offset..][0..@sizeOf(usize)], &size_buff);
    offset += @sizeOf(usize);

    var int_buff: [@sizeOf(u32)]u8 = undefined;
    std.mem.writeInt(u32, &int_buff, header.iterations, .little);
    @memcpy(buf[offset..][0..@sizeOf(u32)], &int_buff);
    offset += @sizeOf(u32);

    std.mem.writeInt(u32, &int_buff, header.mem_cost, .little);
    @memcpy(buf[offset..][0..@sizeOf(u32)], &int_buff);
    offset += @sizeOf(u32);

    std.mem.writeInt(u32, &int_buff, header.parallelism, .little);
    @memcpy(buf[offset..][0..@sizeOf(u32)], &int_buff);
    offset += @sizeOf(u32);

    @memcpy(buf[offset..][0..Config.SALT_LEN], &header.salt);
    offset += Config.SALT_LEN;

    if (header.version == 2) return buf[0..offset];

    @memcpy(buf[offset..][0..Config.ID_LEN], &header.vault_id);
    return buf;
}

pub fn takeDelimiter(
    out: *Writer,
    in: *Reader,
    delimeter: u8,
) !?[]u8 {
    const slice = in.takeDelimiter(delimeter) catch |err| switch (err) {
        error.StreamTooLong => {
            try printInputTooLong(out, in.buffer.len);
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
) !pzcrypt.Secret {
    try out.writeAll(prompt);
    try out.flush();
    // null means stdin was closed; re-prompting would loop forever.
    const line = (try takeDelimiter(out, in, '\n')) orelse return error.EndOfStream;
    // Don't leave the typed text in the stdin buffer for the rest of the session.
    defer std.crypto.secureZero(u8, line);
    const trimmed = std.mem.trim(u8, line, " \r\t");
    if (trimmed.len == 0) return error.EmptyString;
    const input = try pzcrypt.dupeSecret(allocator, trimmed);
    errdefer pzcrypt.freeSecret(allocator, input);
    try flushInput(out, in);
    try out.flush();
    return input;
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

    const index = std.fmt.parseInt(usize, index_slice, 10) catch return error.WrongInput;

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
    const io = std.testing.io;
    const env = std.testing.environ;

    const cwd = env.getPosix("PWD") orelse "/tmp";

    const file_path = try storage.VaultPath.default(allocator, io, cwd, "vault.vault.dat");
    defer allocator.free(file_path);

    var vault = try Vault.init(allocator, io, "blue-penguin", cwd, ".pzpass", "vault.vault.dat");
    defer vault.deinit(allocator);

    try vault.addEntry(allocator, io, "test", "test data");
    try vault.deleteEntry(allocator, 0);

    try vault.updatePassword(allocator, io, "orange-tiger");
}

test "new vault reopens with the same password" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const env = std.testing.environ;

    const cwd = env.getPosix("PWD") orelse "/tmp";
    const file_name = "reopen.vault.dat";
    deleteTestFile(io, cwd, ".pzpass", file_name);
    defer deleteTestFile(io, cwd, ".pzpass", file_name);
    defer deleteTestFile(io, cwd, ".pzpass", file_name ++ ".bak");

    {
        var vault = try Vault.init(allocator, io, "correct-password", cwd, ".pzpass", file_name);
        defer vault.deinit(allocator);
        try vault.addEntry(allocator, io, "first", "one");
        try vault.addEntry(allocator, io, "second", "two");
        try vault.save(allocator, io, cwd, ".pzpass", file_name);
    }

    var vault = try Vault.init(allocator, io, "correct-password", cwd, ".pzpass", file_name);
    defer vault.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), vault.entries.items.len);

    // Replacing in place (as the edit prompt does) keeps the index.
    const updated = try vault.makeEntry(allocator, io, "first", "uno");
    const old = vault.entries.items[0];
    vault.entries.items[0] = updated;
    freeEntry(allocator, old);

    var name: [5]u8 = undefined;
    var data: [3]u8 = undefined;
    try vault.decryptEntry(&vault.entries.items[0], &name, &data);
    try std.testing.expectEqualStrings("first", &name);
    try std.testing.expectEqualStrings("uno", &data);
}

fn expectEntries(allocator: Allocator, vault: *const Vault, expected: []const [2][]const u8) !void {
    try std.testing.expectEqual(expected.len, vault.entries.items.len);
    for (vault.entries.items, expected) |*entry, want| {
        const plain = try vault.decryptEntryAlloc(allocator, entry);
        defer plain.deinit(allocator);
        try std.testing.expectEqualStrings(want[0], plain.name);
        try std.testing.expectEqualStrings(want[1], plain.data);

        const name = try vault.decryptNameAlloc(allocator, entry);
        defer pzcrypt.freeSecret(allocator, name);
        try std.testing.expectEqualStrings(want[0], name);
    }
}

test "entry data swapped between entries fails to decrypt" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = std.testing.environ.getPosix("PWD") orelse "/tmp";
    const file_name = "swap.vault.dat";
    deleteTestFile(io, cwd, ".pzpass", file_name);

    var vault = try Vault.init(allocator, io, "correct-password", cwd, ".pzpass", file_name);
    defer vault.deinit(allocator);
    try vault.addEntry(allocator, io, "aaaa", "1111");
    try vault.addEntry(allocator, io, "bbbb", "2222");

    const items = vault.entries.items;
    std.mem.swap([]u8, &items[0].ciphertext_data, &items[1].ciphertext_data);
    std.mem.swap([Config.NONCE_LEN]u8, &items[0].nonce_data, &items[1].nonce_data);
    std.mem.swap([Config.TAG_LEN]u8, &items[0].tag_data, &items[1].tag_data);

    var name: [4]u8 = undefined;
    var data: [4]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, vault.decryptEntry(&items[0], &name, &data));
    try std.testing.expectError(error.AuthenticationFailed, vault.decryptEntry(&items[1], &name, &data));
}

test "removing an entry from the file is detected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = std.testing.environ.getPosix("PWD") orelse "/tmp";
    const file_name = "removed-entry.vault.dat";
    deleteTestFile(io, cwd, ".pzpass", file_name);
    defer deleteTestFile(io, cwd, ".pzpass", file_name);
    defer deleteTestFile(io, cwd, ".pzpass", file_name ++ ".bak");

    var vault = try Vault.init(allocator, io, "correct-password", cwd, ".pzpass", file_name);
    defer vault.deinit(allocator);
    try vault.addEntry(allocator, io, "keep", "1111");
    try vault.addEntry(allocator, io, "drop", "2222");

    const original = try format.serializeVault(allocator, vault);
    defer allocator.free(original);

    // An attacker can rebuild the file without an entry, but not its MAC.
    try vault.deleteEntry(allocator, 1);
    const shortened = try format.serializeVault(allocator, vault);
    defer allocator.free(shortened);

    const forged = try std.mem.concat(allocator, u8, &.{
        shortened[0 .. shortened.len - Config.MAC_LEN],
        original[original.len - Config.MAC_LEN ..],
    });
    defer allocator.free(forged);
    try storage.writeFile(allocator, io, cwd, ".pzpass", file_name, forged);

    try std.testing.expectError(
        error.VaultMacMismatch,
        Vault.init(allocator, io, "correct-password", cwd, ".pzpass", file_name),
    );
}

test "password change rotates the vault key and deletes the backup" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = std.testing.environ.getPosix("PWD") orelse "/tmp";
    const file_name = "rotate.vault.dat";
    deleteTestFile(io, cwd, ".pzpass", file_name);
    defer deleteTestFile(io, cwd, ".pzpass", file_name);
    defer deleteTestFile(io, cwd, ".pzpass", file_name ++ ".bak");

    {
        var vault = try Vault.init(allocator, io, "old-password", cwd, ".pzpass", file_name);
        defer vault.deinit(allocator);
        try vault.addEntry(allocator, io, "name", "data");
        try vault.save(allocator, io, cwd, ".pzpass", file_name);
        try vault.save(allocator, io, cwd, ".pzpass", file_name); // creates a .bak

        const old_key = vault.vault_key.*;
        try vault.updatePassword(allocator, io, "new-password");
        try std.testing.expect(!std.mem.eql(u8, &old_key, vault.vault_key));
        try expectEntries(allocator, vault, &.{.{ "name", "data" }});

        try vault.save(allocator, io, cwd, ".pzpass", file_name);
        try std.testing.expect(!vault.purge_backup);
    }

    // The pre-rotation backup is gone.
    try std.testing.expectError(
        error.FileNotFound,
        storage.readFileAlloc(allocator, io, cwd, ".pzpass", file_name ++ ".bak"),
    );

    try std.testing.expectError(
        error.AuthenticationFailed,
        Vault.init(allocator, io, "old-password", cwd, ".pzpass", file_name),
    );
    var vault = try Vault.init(allocator, io, "new-password", cwd, ".pzpass", file_name);
    defer vault.deinit(allocator);
    try expectEntries(allocator, vault, &.{.{ "name", "data" }});
}

test "wrong password fails cleanly without corruption" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const env = std.testing.environ;

    const cwd = env.getPosix("PWD") orelse "/tmp";
    const file_name = "wrong-password.vault.dat";

    {
        var vault = try Vault.init(allocator, io, "correct-password", cwd, ".pzpass", file_name);
        defer vault.deinit(allocator);
        try vault.addEntry(allocator, io, "name", "data");
        try vault.save(allocator, io, cwd, ".pzpass", file_name);
    }

    try std.testing.expectError(
        error.AuthenticationFailed,
        Vault.init(allocator, io, "wrong-password", cwd, ".pzpass", file_name),
    );
}

test "corrupt vault file errors instead of silently creating a new vault" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const env = std.testing.environ;

    const cwd = env.getPosix("PWD") orelse "/tmp";
    const file_name = "corrupt.vault.dat";

    try storage.writeFile(allocator, io, cwd, ".pzpass", file_name, "not a vault");

    try std.testing.expectError(
        error.InvalidMagic,
        Vault.init(allocator, io, "any-password", cwd, ".pzpass", file_name),
    );
}

test "tampered header fails to decrypt" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const env = std.testing.environ;

    const cwd = env.getPosix("PWD") orelse "/tmp";
    const file_name = "tampered.vault.dat";

    {
        var vault = try Vault.init(allocator, io, "correct-password", cwd, ".pzpass", file_name);
        defer vault.deinit(allocator);
        try vault.addEntry(allocator, io, "name", "data");
        try vault.save(allocator, io, cwd, ".pzpass", file_name);
    }

    const data = try storage.readFileAlloc(allocator, io, cwd, ".pzpass", file_name);
    defer allocator.free(data);

    const iterations_offset = MAGIC.len + @sizeOf(usize) + Config.SALT_LEN;
    data[iterations_offset] ^= 0x01;

    try storage.writeFile(allocator, io, cwd, ".pzpass", file_name, data);

    try std.testing.expectError(
        error.AuthenticationFailed,
        Vault.init(allocator, io, "correct-password", cwd, ".pzpass", file_name),
    );

    // The vault on disk is left with a tampered header, which would make the
    // next run fail while creating the vault.
    deleteTestFile(io, cwd, ".pzpass", file_name);
    deleteTestFile(io, cwd, ".pzpass", file_name ++ ".bak");
}

fn deleteTestFile(io: std.Io, base_dir: []const u8, sub_dir_name: []const u8, file_name: []const u8) void {
    var base = std.Io.Dir.openDirAbsolute(io, base_dir, .{ .access_sub_paths = true }) catch return;
    defer base.close(io);

    const sub_dir = base.openDir(io, sub_dir_name, .{ .access_sub_paths = true }) catch return;
    defer sub_dir.close(io);

    sub_dir.deleteFile(io, file_name) catch {};
}
