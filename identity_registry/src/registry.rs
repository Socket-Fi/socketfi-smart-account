use soroban_sdk::{xdr::ToXdr, Address, Bytes, Env, String};

use socketfi_shared::{
    registry_errors::RegistryError, ttl::bump_persistent, utils::userid_wallet_key,
};

use crate::data::DataKey;

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
    bump_persistent(e, &key);
    Ok(e.storage().persistent().get(&key))
}

pub fn read_wallet_is_mapped(
    e: &Env,
    platform_validated: String,
    wallet: Address,
) -> Result<bool, RegistryError> {
    let mut salt = Bytes::new(e);
    salt.append(&platform_validated.into());
    salt.push_back(0);
    salt.append(&wallet.to_xdr(e));

    let key = DataKey::HasMap(e.crypto().sha256(&salt).into());

    if let Some(is_mapped) = e.storage().persistent().get::<_, bool>(&key) {
        bump_persistent(e, &key);
        Ok(is_mapped)
    } else {
        Ok(false)
    }
}

pub fn write_wallet_is_mapped(
    e: &Env,
    platform_validated: String,
    wallet: Address,
) -> Result<(), RegistryError> {
    let mut salt = Bytes::new(e);
    salt.append(&platform_validated.into());
    salt.push_back(0);
    salt.append(&wallet.to_xdr(e));

    let key = DataKey::HasMap(e.crypto().sha256(&salt).into());
    e.storage().persistent().set(&key, &true);
    bump_persistent(e, &key);

    Ok(())
}

pub fn delete_wallet_is_mapped(
    e: &Env,
    platform_validated: String,
    wallet: Address,
) -> Result<(), RegistryError> {
    let mut salt = Bytes::new(e);
    salt.append(&platform_validated.into());
    salt.push_back(0);
    salt.append(&wallet.to_xdr(e));

    let key = DataKey::HasMap(e.crypto().sha256(&salt).into());

    e.storage().persistent().remove(&key);

    Ok(())
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
    bump_persistent(e, &key);
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
