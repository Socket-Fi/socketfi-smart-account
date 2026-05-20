use soroban_sdk::{contracttype, Address};

#[derive(Clone)]
#[contracttype]
pub struct CollectNowData {
    pub fee_asset: Address,
    pub previous_deferred_fee_in_base: i128,
    pub previous_deferred_fee_in_asset: i128,
    pub added_fee_in_base: i128,
    pub added_fee_in_asset: i128,
    pub total_in_base: i128,
    pub total_fee_in_asset: i128,
    pub total_tx_amount: i128,
}

#[derive(Clone)]
#[contracttype]
pub struct DeferData {
    pub previous_deferred_fee: i128,
    pub added_base_fee: i128,
    pub updated_deferred_fee: i128,
    pub total_tx_amount: i128,
}

#[derive(Clone)]
#[contracttype]
pub struct CannotProceedData {
    pub previous_deferred_fee: i128,
    pub added_base_fee: i128,
    pub updated_deferred_fee: i128,
    pub max_deferred_fee: i128,
    pub total_tx_amount: i128,
}

#[derive(Clone)]
#[contracttype]
pub enum FeeDecision {
    CollectNow(CollectNowData),
    Defer(DeferData),
    CannotProceed(CannotProceedData),
}
