use socketfi_shared::ttl::{bump_instance, bump_persistent};
use socketfi_webauthn::wallet_error::WalletError;
use soroban_sdk::{crypto::bls12_381::G1Affine, Address, BytesN, Env, Vec};

use crate::data::DataKey;

/// Check whether the wallet has already been initialized.
///
/// Notes:
/// - Initialization is inferred from whether the aggregated BLS key
///   has been stored in persistent storage.
/// - Returns `true` once `DataKey::AggregatedBlsKey` exists.
pub fn is_initialized(env: &Env) -> bool {
    let key = DataKey::AggregatedBlsKey;
    env.storage().persistent().has(&key)
}

/// Read the external owner address from instance storage.
///
/// Notes:
/// - Returns `Some(Address)` if an owner has been set.
/// - Returns `None` if no owner is currently stored.
/// - Uses instance storage because owner data is contract instance state.
pub fn read_owner(env: &Env) -> Option<Address> {
    let key = DataKey::Owner;
    bump_instance(env);
    env.storage().instance().get(&key)
}

/// Write or replace the external owner address in instance storage.
///
/// Notes:
/// - Stores the provided owner address under `DataKey::Owner`.
/// - Overwrites any previously stored owner value.
pub fn write_owner(env: &Env, owner: &Address) {
    let key = DataKey::Owner;
    bump_instance(env);
    env.storage().instance().set(&key, owner);
}

/// Aggregate multiple BLS public keys into a single aggregated key.
///
/// Notes:
/// - Combines keys using BLS G1 point addition.
/// - Assumes keys have already been validated before invocation.
/// - Returns the aggregated public key.
/// - Does not write to contract storage.
pub fn aggregate_bls_keys(env: &Env, bls_keys: Vec<BytesN<96>>) -> Result<BytesN<96>, WalletError> {
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

/// Compute and persist the aggregated BLS public key.
///
/// Notes:
/// - Aggregates the provided BLS public keys.
/// - Stores the resulting aggregated key in persistent storage.
/// - Assumes input validation has already been performed.
pub fn write_agg_bls_key(env: &Env, bls_agg: BytesN<96>) -> Result<(), WalletError> {
    env.storage()
        .persistent()
        .set(&DataKey::AggregatedBlsKey, &bls_agg);

    Ok(())
}

/// Read the aggregated BLS public key from persistent storage.
///
/// Notes:
/// - Returns `Some(BytesN<96>)` if an aggregated key has been stored.
/// - Returns `None` if the wallet has not yet stored an aggregated key.
pub fn read_agg_bls_key(env: &Env) -> Option<BytesN<96>> {
    let key = DataKey::AggregatedBlsKey;

    bump_persistent(&env, &key);
    env.storage().persistent().get(&key)
}

pub fn read_rpid_hash(env: &Env) -> Option<BytesN<32>> {
    let key = DataKey::RpidHash;
    bump_instance(env);
    env.storage().instance().get(&key)
}

pub fn write_rpid_hash(env: &Env, rpid_hash: &BytesN<32>) {
    let key = DataKey::RpidHash;
    bump_instance(env);
    env.storage().instance().set(&key, rpid_hash);
}

/// Store the passkey payload in persistent storage.
///
/// Notes:
/// - Writes the provided passkey bytes under `DataKey::Passkey`.
/// - Overwrites any previously stored passkey value.
pub fn write_passkey(env: &Env, passkey: BytesN<65>) {
    let key = DataKey::Passkey;
    env.storage().persistent().set(&key, &passkey);
    bump_persistent(&env, &key);
}

/// Read the stored passkey payload from persistent storage.
///
/// Notes:
/// - Returns `Some(BytesN<65>)` if a passkey has been stored.
/// - Returns `None` if no passkey is currently set.
pub fn read_passkey(env: &Env) -> Option<BytesN<65>> {
    let key = DataKey::Passkey;
    bump_persistent(&env, &key);
    env.storage().persistent().get(&key)
}
