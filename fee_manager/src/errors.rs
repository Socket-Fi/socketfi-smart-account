use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    UnsupportedAsset = 417,
    MaxPendingFeeNotFound = 423,
    BaseFeeNotConfigured = 424,
    FeeRateNotSet = 425,
    InvalidAmount = 729,
    Unauthorized = 739,
    MaxDeferredFeeExceeded = 749,
}
