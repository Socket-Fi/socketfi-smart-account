use soroban_sdk::{BytesN, Env, Vec};

use crate::data::DataKey;

/// Add validator to the validator set.
///
/// Policy:
/// - First-write-only for a given validator key
///
/// Notes:
/// - Validators are stored as keys in `Map<BytesN<32>, ()>`.
/// - Only membership is tracked; no validator metadata is stored.
pub fn write_add_validator(e: &Env, v: BytesN<32>) {
    let mut m = e
        .storage()
        .persistent()
        .get::<_, soroban_sdk::Map<BytesN<32>, ()>>(&DataKey::Validators)
        .unwrap_or_else(|| soroban_sdk::Map::new(e));

    if m.contains_key(v.clone()) {
        return;
    }

    m.set(v, ());
    e.storage().persistent().set(&DataKey::Validators, &m);
}

/// Remove validator from the validator set.
///
/// Notes:
/// - No effect if validator is not present.
pub fn write_remove_validator(e: &Env, v: BytesN<32>) {
    let mut m = e
        .storage()
        .persistent()
        .get::<_, soroban_sdk::Map<BytesN<32>, ()>>(&DataKey::Validators)
        .unwrap_or_else(|| soroban_sdk::Map::new(e));

    if !m.contains_key(v.clone()) {
        return;
    }

    m.remove(v);

    e.storage().persistent().set(&DataKey::Validators, &m);
}

/// Check whether a validator is currently in the validator set.
///
/// Returns:
/// - `true` if present
/// - `false` otherwise
pub fn read_is_validator(e: &Env, v: BytesN<32>) -> bool {
    e.storage()
        .persistent()
        .get::<_, soroban_sdk::Map<BytesN<32>, ()>>(&DataKey::Validators)
        .map(|m| m.contains_key(v))
        .unwrap_or(false)
}

/// Return all validator public keys.
pub fn read_validators(e: &Env) -> Vec<BytesN<32>> {
    let m = e
        .storage()
        .persistent()
        .get::<_, soroban_sdk::Map<BytesN<32>, ()>>(&DataKey::Validators)
        .unwrap_or(soroban_sdk::Map::new(e));

    m.keys()
}

/// Return current required signature count.
///
/// Current behavior:
/// - Equal to validator count
/// - Returns `0` if validator map is missing
pub fn read_threshold(e: &Env) -> u32 {
    e.storage()
        .persistent()
        .get::<_, soroban_sdk::Map<BytesN<32>, ()>>(&DataKey::Validators)
        .map(|m| m.len())
        .unwrap_or(0)
}
