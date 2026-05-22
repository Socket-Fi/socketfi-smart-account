use soroban_sdk::{contracttype, Bytes, BytesN};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    UsedCreationNonce(BytesN<32>),
    RPIDHash,
}
