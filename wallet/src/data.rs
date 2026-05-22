use soroban_sdk::{contracttype, Bytes, BytesN};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    FactoryContract,
    Owner,
    AggregatedBlsKey,
    Passkey,
    Nonce,
    RpidHash,
    RPID,
}
