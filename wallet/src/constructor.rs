use socketfi_shared::tokens::write_allowance_expiration;
use socketfi_webauthn::wallet_error::WalletError;
use soroban_sdk::{Address, BytesN, Env, Vec};

use crate::state::{write_agg_bls_key, write_owner, write_passkey, write_rpid_hash};
use socketfi_access::access::{
    write_factory, write_fee_manager, write_registry, write_social_router,
};

/// Initialize wallet state during contract construction.
///
/// Notes:
/// - Stores authentication data and linked contract addresses.
/// - Sets initial wallet configuration values used by later token operations.
/// - Returns an error only if aggregated BLS key setup fails.
pub fn init_constructor(
    env: Env,
    passkey: BytesN<65>,
    rpid_hash: BytesN<32>,
    bls_agg: BytesN<96>,
    registry: Address,
    social_router: Address,
    fee_manager: Address,
    factory: Address,
    external_wallet: Option<Address>,
) -> Result<(), WalletError> {
    // Store the passkey payload used by the wallet auth model.
    write_passkey(&env, passkey);

    //Store the configured rp_id hash for the passkey
    write_rpid_hash(&env, &rpid_hash);

    // Aggregate and store the BLS public keys used for signature verification.
    write_agg_bls_key(&env, bls_agg)?;

    // Store linked contract addresses required by wallet flows.
    write_registry(&env, &registry);
    write_fee_manager(&env, &fee_manager);
    write_social_router(&env, &social_router);
    write_factory(&env, &factory);

    if let Some(owner) = external_wallet {
        write_owner(&env, &owner)
    }

    // Set the initial allowance expiration configuration used for approvals.
    write_allowance_expiration(&env, 17_000);

    Ok(())
}
