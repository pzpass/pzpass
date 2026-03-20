pub const MAGIC = "PZPASS".*;
pub const VERSION = 1;

pub const v1 = struct {
    pub const SALT_LEN = 16;
    pub const NONCE_LEN = 12;
    pub const KEY_LEN = 32;
    pub const TAG_LEN = 16;

    pub const MEM_COST = 1 << 16;
    pub const ITERATIONS = 3;
    pub const PARALLELISM = 1;
};
