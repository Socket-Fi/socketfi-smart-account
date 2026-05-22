use soroban_sdk::{contracttype, Bytes, BytesN, Env, Vec};

#[derive(Clone)]
#[contracttype]
pub struct BlsKeyWithPoP {
    pub key: BytesN<96>,
    pub sig: BytesN<192>,
}

#[derive(Clone)]
#[contracttype]
pub struct PasskeySignature {
    pub signature: BytesN<64>,
    pub client_data_json: Bytes,
    pub authenticator_data: Bytes,
}

pub fn extract_bls_keys(e: &Env, bls_keys_pop: Vec<BlsKeyWithPoP>) -> Vec<BytesN<96>> {
    let mut bls_keys: Vec<BytesN<96>> = Vec::new(e);

    for bls_key_pop in bls_keys_pop.iter() {
        bls_keys.push_back(bls_key_pop.key.clone());
    }

    bls_keys
}
