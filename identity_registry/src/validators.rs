use socketfi_shared::ttl::bump_persistent;
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
    let key = DataKey::Validators;
    e.storage().persistent().set(&key, &m);
    bump_persistent(e, &key);
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

    let key = DataKey::Validators;

    e.storage().persistent().set(&key, &m);
    bump_persistent(e, &key);
}

/// Check whether a validator is currently in the validator set.
///
/// Returns:
/// - `true` if present
/// - `false` otherwise
pub fn read_is_validator(e: &Env, v: BytesN<32>) -> bool {
    let key = DataKey::Validators;

    let is_validator = e
        .storage()
        .persistent()
        .get::<_, soroban_sdk::Map<BytesN<32>, ()>>(&key)
        .map(|m| m.contains_key(v))
        .unwrap_or(false);
    bump_persistent(e, &key);
    is_validator
}

/// Return all validator public keys.
pub fn read_validators(e: &Env) -> Vec<BytesN<32>> {
    let key = DataKey::Validators;
    let m = e
        .storage()
        .persistent()
        .get::<_, soroban_sdk::Map<BytesN<32>, ()>>(&key)
        .unwrap_or(soroban_sdk::Map::new(e));
    bump_persistent(e, &key);

    m.keys()
}

/// Return current required signature count.
///
/// Current behavior:
/// - Equal to validator count
/// - Returns `0` if validator map is missing
pub fn read_threshold(e: &Env) -> u32 {
    let key = DataKey::Validators;

    let t = e
        .storage()
        .persistent()
        .get::<_, soroban_sdk::Map<BytesN<32>, ()>>(&key)
        .map(|m| m.len())
        .unwrap_or(0);
    bump_persistent(e, &key);
    t
}
