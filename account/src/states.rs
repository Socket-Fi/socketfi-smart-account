use socketfi_shared::account_error::AccountError;

use soroban_sdk::{contracttype, crypto::bls12_381::G1Affine, Address, BytesN, Env, Vec};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    FactoryContract,
    InstalledWasm,
    Owner,
    Guardians,
    Paused,
    UnpauseApproved,
    AggregatedBlsKey,
    Passkey,
    StellarSigner,
    EvmSigner,
    Nonce,
    RpidHash,
    RPID,
}

/// Check whether this account has already been initialized.
///
/// Initialization is inferred from the presence of the aggregated BLS key.
pub fn is_initialized(env: &Env) -> bool {
    env.storage().instance().has(&DataKey::AggregatedBlsKey)
}

/// Aggregate previously validated BLS public keys.
///
/// The caller must ensure that `bls_keys` is non-empty and every key has
/// already passed the required BLS public-key and proof-of-possession checks.
pub fn aggregate_bls_keys(
    env: &Env,
    bls_keys: Vec<BytesN<96>>,
) -> Result<BytesN<96>, AccountError> {
    let bls = env.crypto().bls12_381();

    let mut keypair_1_array = [0u8; 96];
    bls_keys
        .get_unchecked(0)
        .copy_into_slice(&mut keypair_1_array);

    let mut agg_pk = G1Affine::from_bytes(BytesN::from_array(env, &keypair_1_array));

    let n = bls_keys.len();

    for i in 1..n {
        let mut keypair_i_array = [0u8; 96];
        bls_keys
            .get_unchecked(i)
            .copy_into_slice(&mut keypair_i_array);

        let pk = G1Affine::from_bytes(BytesN::from_array(env, &keypair_i_array));
        agg_pk = bls.g1_add(&agg_pk, &pk);
    }

    Ok(agg_pk.to_bytes())
}

// -----------------------------------------------------------------------------
// Aggregated BLS recovery key
// -----------------------------------------------------------------------------

pub fn write_agg_bls_key(env: &Env, bls_agg: &BytesN<96>) -> Result<(), AccountError> {
    env.storage()
        .instance()
        .set(&DataKey::AggregatedBlsKey, bls_agg);

    Ok(())
}

pub fn read_agg_bls_key(env: &Env) -> Option<BytesN<96>> {
    env.storage().instance().get(&DataKey::AggregatedBlsKey)
}

// -----------------------------------------------------------------------------
// RP ID configuration
// -----------------------------------------------------------------------------

pub fn write_rpid_hash(env: &Env, rpid_hash: &BytesN<32>) {
    env.storage().instance().set(&DataKey::RpidHash, rpid_hash);
}

pub fn read_rpid_hash(env: &Env) -> Option<BytesN<32>> {
    env.storage().instance().get(&DataKey::RpidHash)
}

// -----------------------------------------------------------------------------
// Passkey signer
// -----------------------------------------------------------------------------

pub fn write_passkey(env: &Env, passkey: &BytesN<65>) {
    env.storage().instance().set(&DataKey::Passkey, passkey);
}

pub fn read_passkey(env: &Env) -> Option<BytesN<65>> {
    env.storage().instance().get(&DataKey::Passkey)
}

// -----------------------------------------------------------------------------
// Stellar signer
// -----------------------------------------------------------------------------

pub fn write_stellar_signer(env: &Env, signer: &BytesN<32>) {
    env.storage()
        .instance()
        .set(&DataKey::StellarSigner, signer);
}

pub fn read_stellar_signer(env: &Env) -> Option<BytesN<32>> {
    env.storage().instance().get(&DataKey::StellarSigner)
}

// -----------------------------------------------------------------------------
// EVM signer
// -----------------------------------------------------------------------------

pub fn write_evm_signer(env: &Env, signer: &BytesN<20>) {
    env.storage().instance().set(&DataKey::EvmSigner, signer);
}

pub fn read_evm_signer(env: &Env) -> Option<BytesN<20>> {
    env.storage().instance().get(&DataKey::EvmSigner)
}

// -----------------------------------------------------------------------------
// SocketFi Factory
// -----------------------------------------------------------------------------

pub fn write_factory(env: &Env, factory: &Address) {
    env.storage()
        .instance()
        .set(&DataKey::FactoryContract, factory);
}

pub fn read_factory(env: &Env) -> Option<Address> {
    env.storage().instance().get(&DataKey::FactoryContract)
}

// -----------------------------------------------------------------------------
// SocketFi Factory
// -----------------------------------------------------------------------------

pub fn write_installed_wasm_hash(env: &Env, wasm: &BytesN<32>) {
    env.storage().instance().set(&DataKey::InstalledWasm, wasm);
}

pub fn read_installed_wasm_hash(env: &Env) -> Option<BytesN<32>> {
    env.storage().instance().get(&DataKey::InstalledWasm)
}

// -----------------------------------------------------------------------------
// Active signer management
// -----------------------------------------------------------------------------

/// Remove every possible active signer.
///
/// `RpidHash` is deliberately preserved because it is permanent,
/// account-level RP configuration rather than active-signer state.
///
/// Removing a missing instance-storage key is safe and does not error.
pub fn clear_active_signers(env: &Env) {
    let storage = env.storage().instance();

    storage.remove(&DataKey::Passkey);
    storage.remove(&DataKey::StellarSigner);
    storage.remove(&DataKey::EvmSigner);
}
