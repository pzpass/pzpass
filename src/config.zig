pub const MAGIC = "PZPASS".*;
pub const Config = packed struct {
    pub const VERSION = 1;

    pub const SALT_LEN = 16;
    pub const NONCE_LEN = 12;
    pub const KEY_LEN = 32;
    pub const TAG_LEN = 16;

    pub const MEM_COST: u32 = 1 << 18;
    pub const ITERATIONS: u32 = 5;
    pub const PARALLELISM: u24 = 1;

    pub const ENTRY_LEN = 4096;
};
