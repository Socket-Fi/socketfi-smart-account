use soroban_sdk::{contracttype, token, Address, Env, Map, Vec};

use crate::ttl::{bump_instance, bump_persistent};

/// Shared storage keys for token utilities and asset configuration.
///
/// NOTE:
/// - `AllowanceExpiration` is stored as a ledger offset, not an absolute ledger.
/// - Spend limits are stored in instance storage because they are contract-wide config.
/// - Supported assets are stored in persistent storage as a set-like `Map<Address, ()>`.
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    /// Relative ledger offset used when creating token approvals.
    AllowanceExpiration,

    /// Per-asset spend limit override.
    SpendLimit(Address),

    /// Set of assets supported by the caller contract.
    SupportedAssets,
}

// -----------------------------------------------------------------------------
// Token Transfers
// -----------------------------------------------------------------------------

/// Transfers `amount` of `asset` from `from` into the current contract.
///
/// REQUIREMENTS:
/// - `from` must authorize the transfer according to token contract rules.
/// - `amount` should be valid and non-negative according to caller logic.
///
/// NOTE:
/// - This helper does not validate amount or auth itself.
/// - The receiving address is always `env.current_contract_address()`.
pub fn take_asset(env: &Env, from: &Address, asset: &Address, amount: i128) {
    let client = token::Client::new(env, asset);
    let to = env.current_contract_address();
    client.transfer(from, &to, &amount);
}

/// Transfers `amount` of `asset` from the current contract to `to`.
///
/// REQUIREMENTS:
/// - The current contract must hold sufficient balance.
/// - `amount` should be valid and non-negative according to caller logic.
pub fn send_asset(env: &Env, to: &Address, asset: &Address, amount: i128) {
    let client = token::Client::new(env, asset);
    let from = env.current_contract_address();
    client.transfer(&from, to, &amount);
}

/// Spends tokens from the smart wallet using allowance-based `transfer_from`.
///
/// FLOW:
/// - The current contract is the smart wallet holding the tokens.
/// - `spender` is an external wallet/account approved by the smart wallet.
/// - The approved `spender` can transfer tokens from the smart wallet
///   to `to` within the allowed allowance.
///
/// IMPORTANT:
/// - The smart wallet (current contract) must have previously approved
///   `spender` for at least `amount` tokens.
/// - Internally this executes:
///   `transfer_from(current_contract, spender, to, amount)`.
/// - Tokens are deducted from the smart wallet balance.
pub fn spend_asset(env: &Env, spender: &Address, asset: &Address, amount: i128, to: &Address) {
    let client = token::Client::new(env, asset);
    let from = env.current_contract_address();
    client.transfer_from(&spender, &from, to, &amount);
}

// -----------------------------------------------------------------------------
// Token Reads
// -----------------------------------------------------------------------------

/// Returns the current contract's balance for `asset`.
pub fn read_balance(env: &Env, asset: &Address) -> i128 {
    let client = token::Client::new(env, asset);
    let of = env.current_contract_address();
    client.balance(&of)
}

/// Returns the allowance granted by the current contract to `spender`.
///
/// NOTE:
/// - Reads allowance where:
///   - owner = current contract
///   - spender = provided address
pub fn read_allowance(env: &Env, asset: &Address, spender: &Address) -> i128 {
    let client = token::Client::new(env, asset);
    let from = env.current_contract_address();
    client.allowance(&from, spender)
}

// -----------------------------------------------------------------------------
// Token Approval Configuration
// -----------------------------------------------------------------------------

/// Approves `spender` to spend `amount` from the current contract.
///
/// EXPIRATION:
/// - Approval expiration is computed as:
///   `current_ledger_sequence + stored_allowance_offset`
///
/// IMPORTANT:
/// - `AllowanceExpiration` stores a relative offset, not an absolute sequence.
/// - Overflow will panic with `expect("invalid allowance expiration")`.
/// - Caller is responsible for deciding safe allowance amounts.
pub fn write_approve(env: &Env, asset: &Address, spender: &Address, amount: &i128) {
    let client = token::Client::new(env, asset);
    let from = env.current_contract_address();

    let expiration = read_allowance_expiration(env)
        .checked_add(env.ledger().sequence())
        .expect("invalid allowance expiration");

    client.approve(&from, spender, amount, &expiration);
}

/// Stores the allowance expiration offset in ledgers.
///
/// NOTE:
/// - This is a relative offset from the current ledger sequence at approval time.
pub fn write_allowance_expiration(env: &Env, ledger_offset: u32) {
    bump_instance(env);
    env.storage()
        .instance()
        .set(&DataKey::AllowanceExpiration, &ledger_offset);
}

/// Returns the configured allowance expiration offset.
///
/// DEFAULT:
/// - `17_000` ledgers if not explicitly configured.
pub fn read_allowance_expiration(env: &Env) -> u32 {
    bump_instance(env);
    env.storage()
        .instance()
        .get(&DataKey::AllowanceExpiration)
        .unwrap_or(17_000u32)
}

// -----------------------------------------------------------------------------
// Spend Limits
// -----------------------------------------------------------------------------

/// Returns the spend limit for a specific asset.
///
/// BEHAVIOR:
/// - Uses the asset-specific limit if present.
/// - Otherwise falls back to `DefaultSpendLimit`.
///
/// NOTE:
/// - A missing default also falls back to default.
pub fn read_limit(env: &Env, asset: Address) -> Option<i128> {
    bump_instance(env);
    env.storage().instance().get(&DataKey::SpendLimit(asset))
}

/// Stores the spend limit for a specific asset.
pub fn write_limit(env: &Env, asset: Address, limit: i128) {
    bump_instance(env);
    env.storage()
        .instance()
        .set(&DataKey::SpendLimit(asset), &limit);
}

// -----------------------------------------------------------------------------
// Supported Assets Set
// -----------------------------------------------------------------------------

/// Returns true if `asset` is in the supported assets set.
///
/// NOTE:
/// - Defaults to `false` if the storage key does not exist.
/// - Uses `Map<Address, ()>` as a set representation.
pub fn read_is_supported_asset(e: &Env, asset: Address) -> bool {
    let key = DataKey::SupportedAssets;

    if let Some(map) = e.storage().persistent().get::<_, Map<Address, ()>>(&key) {
        bump_persistent(e, &key);
        map.contains_key(asset)
    } else {
        false
    }
}

/// Returns all supported assets.
///
/// NOTE:
/// - Returns an empty vector if the set has not been initialized.
/// - Ordering depends on map key ordering and should not be relied on.
pub fn read_supported_assets(e: &Env) -> Vec<Address> {
    let key = DataKey::SupportedAssets;

    if let Some(assets) = e.storage().persistent().get::<_, Map<Address, ()>>(&key) {
        bump_persistent(e, &key);
        assets.keys()
    } else {
        Vec::new(e)
    }
}

/// Adds an asset to the supported assets set.
///
/// BEHAVIOR:
/// - If the asset already exists, this function does nothing.
/// - Otherwise, it inserts the asset into the set.
///
/// IMPORTANT:
/// - This function does NOT return an error on duplicates.
/// - Authorization must be enforced by the caller.
pub fn write_add_asset(e: &Env, asset: Address) {
    let key = DataKey::SupportedAssets;
    let mut m: Map<Address, ()> = e
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| Map::new(e));

    if m.contains_key(asset.clone()) {
        return;
    }

    m.set(asset, ());

    e.storage().persistent().set(&key, &m);
    bump_persistent(e, &key);
}

/// Removes an asset from the supported assets set.
///
/// BEHAVIOR:
/// - If the asset does not exist, this function does nothing.
/// - Otherwise, it removes the asset from the set.
///
/// IMPORTANT:
/// - This function does NOT return an error if the asset is absent.
/// - Authorization must be enforced by the caller.
pub fn write_remove_asset(e: &Env, asset: Address) {
    let mut m = e
        .storage()
        .persistent()
        .get::<_, Map<Address, ()>>(&DataKey::SupportedAssets)
        .unwrap_or_else(|| Map::new(e));

    if !m.contains_key(asset.clone()) {
        return;
    }

    m.remove(asset);
    let key = DataKey::SupportedAssets;
    e.storage().persistent().set(&key, &m);
    bump_persistent(e, &key);
}
