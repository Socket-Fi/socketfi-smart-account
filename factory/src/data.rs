use soroban_sdk::{contracttype, Address, BytesN};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    UsedCreationNonce(BytesN<32>),
    RPIDHash,
    ExpectedNetwork,
    RegisteredAccount(Address),
}
