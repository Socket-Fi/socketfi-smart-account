use soroban_sdk::{contracttype, Address, Bytes, BytesN};

#[derive(Clone)]
#[contracttype]
pub struct AccessSettings {
    pub default_allowance: i128,
    pub g_account: Option<Address>,
}
#[derive(Clone)]
#[contracttype]
pub struct PasskeySignature {
    pub signature: BytesN<64>,
    pub client_data_json: Bytes,
    pub authenticator_data: Bytes,
}

#[derive(Clone)]
#[contracttype]
pub struct AuthContext {
    pub nonce: BytesN<32>,
    pub valid_until_ledger: u32,
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
