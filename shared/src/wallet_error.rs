use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum WalletError {
    // ============================================================
    // Generic
    // ============================================================
    InvalidSignature = 100,

    // ============================================================
    // Wallet lifecycle
    // ============================================================
    AlreadyInitialized = 200,
    PasskeyNotFound = 201,
    RpidNotFound = 202,
    WalletVersionNotFound = 203,

    // ============================================================
    // BLS validation
    // ============================================================
    InvalidBlsKey = 300,
    InvalidPoPSignature = 301,
    TooManyKeys = 302,
    InsufficientKeys = 303,
    DuplicateKeys = 304,
    MissingBlsKeys = 305,
    KeyAtInfinity = 306,

    // ============================================================
    // WebAuthn / Passkey
    // ============================================================
    ClientDataTooLarge = 400,
    InvalidClientDataType = 401,
    InvalidChallenge = 402,
    InvalidRpIdHash = 403,
    InvalidAuthenticatorData = 404,
    UserPresenceRequired = 405,
    UserVerificationRequired = 406,

    // ============================================================
    // Network / Replay
    // ============================================================
    InvalidNetwork = 500,
    NonceAlreadyUsed = 501,

    // ============================================================
    // Guardian
    // ============================================================
    MaxGuardiansExceeded = 600,
    DuplicateGuardian = 601,
    GuardianNotFound = 602,
    UnauthorizedGuardian = 603,
    InvalidGuardian = 604,

    // ============================================================
    // Guardian removal
    // ============================================================
    RemovalAlreadyScheduled = 700,
    RemovalNotScheduled = 701,
    GuardianRemovalDelayNotElapsed = 702,

    // ============================================================
    // Pause
    // ============================================================
    WalletPaused = 800,
    UnpauseNotApproved = 801,
}
