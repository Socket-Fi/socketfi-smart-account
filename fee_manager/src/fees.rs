use soroban_sdk::{Address, Env};

use crate::data::DataKey;
use crate::errors::ContractError;
use socketfi_shared::{constants::PRECISION, tokens::read_is_supported_asset, ttl::bump_instance};

// ---------------------------------------------------------------------
// Base Fee (USDC-denominated)
// ---------------------------------------------------------------------
// NOTE:
// - Stored in instance storage (shared across all users)
// - Returns Option because it may not be initialized yet (constructor responsibility)
// - Caller should handle None safely (usually fallback or error)

pub fn read_base_fee(e: &Env) -> Result<i128, ContractError> {
    bump_instance(e);
    e.storage()
        .instance()
        .get(&DataKey::BaseFee)
        .ok_or(ContractError::BaseFeeNotConfigured)
}

pub fn write_base_fee(e: &Env, fee: i128) {
    // ASSUMPTION: validation (fee > 0) is handled at contract level
    e.storage().instance().set(&DataKey::BaseFee, &fee);
    bump_instance(e);
}

// ---------------------------------------------------------------------
// Max Deferred Fee (USDC-denominated)
// ---------------------------------------------------------------------
// NOTE:
// - Hard cap for how much fee can accumulate before forcing settlement
// - Stored in instance storage
// - Returns Result (unlike base fee) → treated as REQUIRED config

pub fn read_max_deferred_fee(e: &Env) -> Result<i128, ContractError> {
    e.storage()
        .instance()
        .get(&DataKey::MaxDeferredFee)
        .ok_or(ContractError::MaxDeferredFeeNotFound)
}

pub fn write_max_deferred_fee(e: &Env, fee: i128) {
    // ASSUMPTION: validated externally (fee > 0 and >= base_fee)
    e.storage().instance().set(&DataKey::MaxDeferredFee, &fee);
    bump_instance(e);
}

// ---------------------------------------------------------------------
// Deferred Fee Per User (USDC-denominated)
// ---------------------------------------------------------------------
// NOTE:
// - Stored in persistent storage (per-user state)
// - Defaults to 0 if not set (safe fallback)
// - Uses Address as part of DataKey → isolated per user

pub fn read_deferred_fee(e: &Env, user: &Address) -> i128 {
    e.storage()
        .persistent()
        .get(&DataKey::DeferredFee(user.clone()))
        .unwrap_or(0)
}

pub fn write_deferred_fee(e: &Env, user: &Address, amount: i128) {
    // NOTE:
    // - No validation here → contract layer must ensure correctness
    // - Setting to 0 effectively "clears" deferred fee
    bump_instance(e);
    e.storage()
        .persistent()
        .set(&DataKey::DeferredFee(user.clone()), &amount);
}

// ---------------------------------------------------------------------
// Fee Asset Rates (Conversion: base → asset)
// ---------------------------------------------------------------------
// NOTE:
// - Stored in persistent storage per asset
// - PRECISION is used for fixed-point math
// - Requires asset to already be registered as supported

pub fn read_fee_asset_rate(e: &Env, asset: &Address) -> Result<i128, ContractError> {
    // SAFETY:
    // - Prevents reading rate for unsupported asset
    if !read_is_supported_asset(&e, asset.clone()) {
        return Err(ContractError::UnsupportedFeeAsset);
    }

    e.storage()
        .persistent()
        .get(&DataKey::FeeAssetRate(asset.clone()))
        .ok_or(ContractError::FeeRateNotSet)
}

pub fn write_fee_asset_rate(e: &Env, asset: &Address, rate: i128) {
    // ASSUMPTION:
    // - rate > 0 validated externally
    // - asset already added to supported assets
    e.storage()
        .persistent()
        .set(&DataKey::FeeAssetRate(asset.clone()), &rate);
}

pub fn delete_fee_asset_rate(e: &Env, asset: &Address) {
    // NOTE:
    // - Safe to call even if key doesn't exist
    // - Typically called when removing supported asset
    e.storage()
        .persistent()
        .remove(&DataKey::FeeAssetRate(asset.clone()));
}

/// Converts a base fee into the selected asset denomination.
///
/// Formula:
/// ceil(total_fee * asset_rate * 10^decimals / PRECISION²)
///
/// Note:
/// - `total_fee` uses PRECISION fixed-point precision.
/// - `asset_rate` uses PRECISION fixed-point precision.
/// - `decimals` is the target asset decimal precision.
/// - Rounds up to avoid under-collecting protocol fees.

pub fn convert_base_to_asset(
    total_fee: i128,
    asset_rate: i128,
    decimals: u32,
) -> Result<i128, ContractError> {
    if total_fee < 0 || asset_rate <= 0 || PRECISION <= 0 {
        return Err(ContractError::InvalidAmount);
    }

    if total_fee == 0 {
        return Ok(0);
    }

    let token_precision = 10_i128
        .checked_pow(decimals)
        .ok_or(ContractError::MathOverflow)?;

    let numerator = total_fee
        .checked_mul(asset_rate)
        .and_then(|v| v.checked_mul(token_precision))
        .ok_or(ContractError::MathOverflow)?;

    let denominator = PRECISION
        .checked_mul(PRECISION)
        .ok_or(ContractError::MathOverflow)?;

    numerator
        .checked_add(denominator - 1)
        .and_then(|v| v.checked_div(denominator))
        .ok_or(ContractError::MathOverflow)
}
