use soroban_sdk::{contracttype, Address};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    BaseFee,
    MaxDeferredFee,
    FeeAssetRate(Address),
    DeferredFee(Address),
}
