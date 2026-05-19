use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum WalletError {
    InvalidSignature = 99,
    AlreadyInitialized = 411,
    ExceedMaxAllowance = 719,
    InvalidLimit = 723,
    InvalidAmount = 729,
    InvalidInvokeContract = 735,
    InvalidInvokeFunction = 737,
    TooManyKeys = 739,
    ClientDataTooLarge = 1999,
    InvalidClientDataType = 2009,
    InvalidChallenge = 2019,
    InvalidRpIdHash = 2029,
    UserPresenceRequired = 2039,
    UserVerificationRequired = 2049,
    InvalidPoPSignature = 2051,
    MissingBlsKeys = 2055,
    NonceAlreadyUsed = 2075,
    RpidNotFound = 2085,
    InvalidNetwork = 2095,
    InvalidAuthenticatorData=2105
}
