pub const MAX_LEN: u32 = 256;
pub const MAX_BLS_KEYS: u32 = 5;
pub const DAY_IN_LEDGERS: u32 = 100;
// pub const DAY_IN_LEDGERS: u32 = 17280;

pub const DEFAULT_CLAIM_PERIOD: u64 = 14 * DAY_IN_LEDGERS as u64;
pub const UPGRADE_VOTING_DURATION: u64 = 7 * DAY_IN_LEDGERS as u64;
pub const VOTING_THRESHOLD: u32 = 75;
pub const RATE_PRECISION: i128 = 10_000_000;
pub const DST: &str = "BLS_AUTH_XMD:SHA-256_SSWU_SOCKETFI";
