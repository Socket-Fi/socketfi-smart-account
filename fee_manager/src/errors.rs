use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ContractError {
    MaxDeferredFeeNotFound = 423,
    BaseFeeNotConfigured = 424,
    FeeRateNotSet = 425,
    InvalidAmount = 729,
    MathOverflow = 733,
    Unauthorized = 739,
    InvalidFeeConfig = 811,
    InvalidDeferredFee = 831,
    UnsupportedFeeAsset = 901,
    FeeExceedsMaximum = 911,
    MaxDeferredFeeExceeded = 921,
    InvalidMaxTotalFee = 931,
}
