pub const MAGIC = "PZPASS".*;
pub const Config = packed struct {
    /// v1: vault key wrapped without associated data.
    /// v2: vault key wrapped with the header as associated data.
    /// v3: v2 + vault/entry ids bound into each entry's associated data,
    ///     and an HMAC over the whole file to protect the entry list.
    pub const VERSION = 3;

    pub const SALT_LEN = 16;
    pub const NONCE_LEN = 12;
    pub const KEY_LEN = 32;
    pub const TAG_LEN = 16;
    pub const ID_LEN = 16;
    pub const MAC_LEN = 32;

    pub const MEM_COST: u32 = 1 << 18;
    pub const ITERATIONS: u32 = 5;
    pub const PARALLELISM: u32 = 1;

    pub const ENTRY_LEN = 4096;
};
