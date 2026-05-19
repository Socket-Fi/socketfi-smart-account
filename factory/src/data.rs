use soroban_sdk::{contracttype, Bytes, BytesN};

#[derive(Clone)]
#[contracttype]
pub struct BlsKeyWithPoP {
    pub key: BytesN<96>,
    pub sig: BytesN<192>,
}

#[derive(Clone)]
#[contracttype]
pub struct PasskeyWithPoP {
    pub key: BytesN<65>,
    pub sig: BytesN<64>,
    pub client_data_json: Bytes,
    pub authenticator_data: Bytes,
}

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    UsedCreationNonce(BytesN<32>),
    RPIDHash,
}
