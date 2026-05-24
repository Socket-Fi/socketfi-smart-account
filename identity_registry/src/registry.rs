use soroban_sdk::{Address, Env, String};

use socketfi_shared::{registry_errors::RegistryError, utils::userid_wallet_key};

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
