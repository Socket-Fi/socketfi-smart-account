use soroban_sdk::{contracttype, Address};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FeePreference {
    pub asset: Address,
    pub max_total_fee: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CannotProceedReason {
    UnsupportedFeeAsset = 0,
    FeeExceedsMaximum = 1,
    MaxDeferredFeeExceeded = 2,
    InvalidMaxTotalFee = 3,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FeeDecision {
    CollectNow(CollectNowData),
    Defer(DeferData),
    CannotProceed(CannotProceedData),
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectNowData {
    pub fee_asset: Address,
    pub total_fee_in_base: i128,
    pub total_fee_in_asset: i128,
    pub max_total_fee: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeferData {
    pub updated_deferred_fee: i128,
    pub max_deferred_fee: i128,
}
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CannotProceedData {
    pub reason: CannotProceedReason,
    pub fee_asset: Option<Address>,
    pub total_fee_in_base: i128,
    pub total_fee_in_asset: Option<i128>,
    pub max_total_fee: Option<i128>,
    pub max_deferred_fee: i128,
}
