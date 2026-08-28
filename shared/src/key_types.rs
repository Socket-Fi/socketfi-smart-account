use soroban_sdk::{contracttype, Address, Bytes, BytesN, Env, Vec};

#[derive(Clone)]
#[contracttype]
pub struct BlsKeyWithPoP {
    pub key: BytesN<96>,
    pub sig: BytesN<192>,
}

#[contracttype]
#[derive(Clone)]
pub struct BlsSignature {
    pub signature: BytesN<192>,
}
#[derive(Clone)]
#[contracttype]
pub struct PasskeySignature {
    pub signature: BytesN<64>,
    pub client_data_json: Bytes,
    pub authenticator_data: Bytes,
}

#[contracttype]
#[derive(Clone)]
pub struct StellarSignature {
    pub signature: BytesN<64>,
}

#[contracttype]
#[derive(Clone)]
pub struct EvmSignature {
    pub signature: BytesN<64>,
    pub recovery_id: u32,
}

#[derive(Clone)]
#[contracttype]
pub struct GuardianInfo {
    pub address: Address,
    pub removal_time: Option<u32>,
}

#[contracttype]
#[derive(Clone)]
pub struct PasskeyAccountSigner {
    pub public_key: BytesN<65>,
    pub pop_signature: PasskeySignature,
}

#[contracttype]
#[derive(Clone)]
pub struct StellarAccountSigner {
    pub public_key: BytesN<32>,
    pub address: Address,
}

#[contracttype]
#[derive(Clone)]
pub struct EvmAccountSigner {
    pub address: BytesN<20>,
    pub pop_signature: EvmSignature,
}

#[contracttype]
#[derive(Clone)]
pub enum AccountSigner {
    Passkey(PasskeyAccountSigner),
    Stellar(StellarAccountSigner),
    Evm(EvmAccountSigner),
}

#[contracttype]
#[derive(Clone)]
pub enum AccountCommitment {
    Passkey(BytesN<65>),
    Stellar(BytesN<32>),
    Evm(BytesN<20>),
}

pub fn extract_bls_keys(e: &Env, bls_keys_pop: Vec<BlsKeyWithPoP>) -> Vec<BytesN<96>> {
    let mut bls_keys: Vec<BytesN<96>> = Vec::new(e);

    for bls_key_pop in bls_keys_pop.iter() {
        bls_keys.push_back(bls_key_pop.key.clone());
    }

    bls_keys
}
