use soroban_sdk::{contracttype, Bytes, BytesN};

#[derive(Clone)]
#[contracttype]
pub struct PasskeySignature {
    pub signature: BytesN<64>,
    pub client_data_json: Bytes,
    pub authenticator_data: Bytes,
}

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
