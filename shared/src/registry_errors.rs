use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RegistryError {
    DuplicateValidator = 101,
    ValidatorAlreadyExists = 103,
    InvalidThreshold = 106,
    NotValidator = 107,
    IncorrectNumberOfSignatures = 108,
    PlatformNotSupported = 409,
    UnsupportedAsset = 417,
    UseridAlreadyMapped = 443,
    PasskeyAlreadyMapped = 444,
    NotClaimable = 457,
    Expired = 459,
    Unauthorized = 461,
    NotRefundable = 463,
    InvalidAmount = 729,
    InvalidUserId = 742,
    UpperNotAllowed = 743,
    SpacesNotAllowed = 744,
    MaxLengthExceeded = 745,
    IdentityNotFound = 4001,
    NotRegistryManager = 4051,
    FactoryNotSet = 4101,
    WalletAlreadyMapped = 5001,
}
