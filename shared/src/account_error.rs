use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum AccountError {
    // ============================================================
    // Generic
    // ============================================================
    InvalidSignature = 100,
    InvalidConfig = 121,

    // ============================================================
    // Account lifecycle
    // ============================================================
    AlreadyInitialized = 200,
    PasskeyNotFound = 201,
    RpidNotFound = 202,
    AccountVersionNotFound = 203,

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
    // Stellar / Signer
    // ============================================================
    StellarSignerMismatch = 420,
    InvalidStellarSigner = 421,

    // ============================================================
    // Stellar / Classic Account
    // ============================================================
    StellarSignerNotFound = 456,

    // ============================================================
    // EVM / Ethereum Account
    // ============================================================
    InvalidEvmRecoveryId = 471,
    EvmSignerNotFound = 473,

    // ============================================================
    // Network / Replay
    // ============================================================
    InvalidNetwork = 500,
    NonceAlreadyUsed = 501,
    CreationProofExpired = 502,
    InvalidCreationExpiry = 503,

    // ============================================================
    // migration
    // ============================================================
    MigrationNotRequired = 550,

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
    AccountPaused = 800,
    UnpauseNotApproved = 801,

    InvalidSessionPolicy = 811,
    SessionRevoked = 812,
    SessionAlreadyExists = 813,
    SessionNotFound = 814,
    SessionUnavailable = 815,
    SessionUnauthorized = 816,
    SessionLimitExceeded = 817,
    ArithmeticOverflow = 818,
}
