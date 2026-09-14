use soroban_sdk::{symbol_short, Symbol};

pub const MAX_LEN: u32 = 256;
pub const MIN_BLS_KEYS: u32 = 2;
pub const MAX_BLS_KEYS: u32 = 5;
pub const MAX_GUARDIANS: u32 = 5;
pub const DAY_IN_LEDGERS: u32 = 17280;
pub const DAY_IN_SECONDS: u64 = 86400;
pub const MAX_AUTH_WINDOW_LEDGER: u32 = 60;
/// Maximum lifetime of an account-creation proof (~10 minutes at 5s/ledger).
pub const MAX_CREATION_WINDOW_LEDGERS: u32 = 120;
pub const CREATION_DOMAIN: &[u8] = b"SOCKETFI_CREATE_ACCOUNT_POP_V2";
pub const GUARDIAN_REMOVAL_DELAY_LEDGERS: u32 = DAY_IN_LEDGERS;
pub const DEFAULT_CLAIM_PERIOD_SECONDS: u64 = 7 * DAY_IN_SECONDS;
pub const UPGRADE_VOTING_DURATION_SECONDS: u64 = 7 * DAY_IN_SECONDS;
pub const VOTING_THRESHOLD: u32 = 75;
pub const SESSION_VERSION: u32 = 1;
pub const MAX_SESSION_LIFETIME_LEDGERS: u32 = 1_555_200; // ~90 days at 5s/ledger
pub const MAX_PERMISSIONS: u32 = 16;
pub const MAX_SPEND_LIMITS: u32 = 8;
pub const MAX_CONTEXTS: u32 = 32;
pub const MAX_RECIPIENTS: u32 = 16;

pub const DST: &str = "BLS_AUTH_XMD:SHA-256_SSWU_SOCKETFI";
pub const SESSION_ID_DOMAIN: &[u8] = b"SOCKETFI_SESSION_POLICY_V1";
pub const SESSION_POP_DOMAIN: &[u8] = b"SOCKETFI_SESSION_POP_V1";
pub const ROTATION_DOMAIN: &[u8] = b"SOCKETFI_ROTATE_ACCOUNT_V1";
pub const RECOVER_DOMAIN: &[u8] = b"SOCKETFI_RECOVER_ACCOUNT_V1";
pub const ETH_PERSONAL_SIGN_PREFIX_32: &[u8] = b"\x19Ethereum Signed Message:\n32";

pub const TRANSFER_FN: Symbol = symbol_short!("transfer");
pub const APPROVE_FN: Symbol = symbol_short!("approve");
pub const BURN_FN: Symbol = symbol_short!("burn");
