use soroban_sdk::{contracttype, BytesN};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    UsedCreationNonce(BytesN<32>),
    RPIDHash,
}
