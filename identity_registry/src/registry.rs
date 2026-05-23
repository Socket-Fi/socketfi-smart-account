use soroban_sdk::{Address, BytesN, Env, String};

use socketfi_shared::{
    registry_errors::RegistryError,
    utils::{passkey_wallet_key, userid_wallet_key, DataKey},
};

/// Reads the wallet bound to a given `(platform, user_id)` identity.
///
/// Returns:
/// - `Ok(Some(Address))` if the identity has been registered
/// - `Ok(None)` if no mapping exists
///
/// Design notes:
/// - Key derivation is delegated to `socketfi_shared::utils::userid_wallet_key`,
///   ensuring a single canonical implementation across contracts.
///
pub fn read_userid_wallet_map(
    e: &Env,
    platform: String,
    user_id: String,
) -> Result<Option<Address>, RegistryError> {
    let key = userid_wallet_key(e, platform, user_id)?;
    Ok(e.storage().persistent().get(&key))
}

/// Writes a new `(platform, user_id) -> wallet` mapping.
///
/// Write policy:
/// - first-write-only
/// - rebinding is explicitly rejected if the identity is already mapped
///
/// Returns:
/// - `Ok(())` on successful first-time registration
/// - `Err(ContractError::UseridAlreadyMapped)` if the identity already exists
///
/// Design notes:
/// - Uses shared key derivation logic to ensure consistency with read paths.
/// - Persistent storage is used because identity bindings are long-lived registry state.
pub fn write_userid_wallet_map(
    e: &Env,
    platform: String,
    userid: String,
    wallet: Address,
) -> Result<(), RegistryError> {
    let key = userid_wallet_key(e, platform, userid)?;

    // Prevent silent overwrite of an existing identity binding.
    if e.storage().persistent().has(&key) {
        return Err(RegistryError::UseridAlreadyMapped);
    }

    e.storage().persistent().set(&key, &wallet);
    Ok(())
}

pub fn remove_userid_wallet_map(
    e: &Env,
    platform: String,
    user_id: String,
) -> Result<(), RegistryError> {
    let key = userid_wallet_key(e, platform, user_id)?;

    if !e.storage().persistent().has(&key) {
        return Err(RegistryError::IdentityNotFound);
    }

    e.storage().persistent().remove(&key);
    Ok(())
}

/// Writes a new `passkey -> wallet` mapping.
///
/// Write policy:
/// - first-write-only
/// - rebinding is explicitly rejected if the passkey is already mapped
///
/// Returns:
/// - `Ok(())` on successful first-time registration
/// - `Err(ContractError::PasskeyAlreadyMapped)` if the passkey already exists
///
/// Design notes:
/// - Uses shared key derivation (`passkey_wallet_key`) for consistency across contracts.
/// - Persistent storage is used to ensure passkey bindings remain durable.
pub fn write_passkey_wallet_map(
    e: &Env,
    passkey: BytesN<65>,
    wallet: Address,
) -> Result<(), RegistryError> {
    let key = passkey_wallet_key(e, passkey)?;

    // Prevent silent overwrite of an existing passkey binding.
    if e.storage().persistent().has(&key) {
        return Err(RegistryError::PasskeyAlreadyMapped);
    }

    e.storage().persistent().set(&key, &wallet);
    Ok(())
}

/// Reads the wallet bound to a given passkey.
///
/// Returns:
/// - `Ok(Some(Address))` if the passkey has been registered
/// - `Ok(None)` if no mapping exists
///
/// Design notes:
/// - Key derivation is delegated to shared utilities for consistency.
///
/// Audit notes:
/// - Lookup correctness depends on exact passkey byte match.
/// - No normalization is applied; any difference in passkey bytes results in a miss.
/// - Returning `Option<Address>` avoids forcing error handling for simple existence checks.
pub fn read_passkey_wallet_map(
    e: &Env,
    passkey: BytesN<65>,
) -> Result<Option<Address>, RegistryError> {
    let key = passkey_wallet_key(e, passkey)?;

    Ok(e.storage().persistent().get::<DataKey, Address>(&key))
}
