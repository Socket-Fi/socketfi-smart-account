use socketfi_access::access::read_fee_manager;
use socketfi_shared::fee_types::FeeDecision;
use socketfi_webauthn::wallet_error::WalletError;
use soroban_sdk::{vec, Address, Env, IntoVal, Symbol, Val};

use crate::{data::PasskeySignature, invocation_auth::__fee_deep_auth};

enum FeeMode {
    ChargeCurrentFee,
    ExistingBalanceOnly,
}

// A passkey-signed transaction represents a new user-authorized wallet action,
// so the current transaction fee should be charged.
//
// Calls without a passkey signature are treated as externally submitted transaction
// settlement paths and should only charge already-deferred fee balances.
fn resolve_fee_mode(passkey_sig: &Option<PasskeySignature>) -> FeeMode {
    if passkey_sig.is_some() {
        FeeMode::ChargeCurrentFee
    } else {
        FeeMode::ExistingBalanceOnly
    }
}

// Handles protocol fee accounting for wallet transactions.
//
// The wallet first asks the fee manager for a fee decision. Based on that
// decision, the wallet either:
// - collects the fee immediately,
// - defers the fee for later settlement, or
// - rejects the transaction if the deferred-fee limit would be exceeded.
//
// Important:
// Fee authorization must be done in fee-asset units, not base-fee units.
// The actual token transfer performed during settlement uses the fee asset,
// so the wallet authorizes:
//
// previous_deferred_fee_in_asset + added_fee_in_asset
//
// before invoking settle_wallet_fee.
pub fn handle_transaction_fee(
    env: &Env,
    tx_asset: Address,
    tx_amount: i128,
    passkey_sig: &Option<PasskeySignature>,
) -> Result<(), WalletError> {
    let fee_manager = read_fee_manager(env).ok_or(WalletError::FeeManagerNotFound)?;

    let wallet = env.current_contract_address();
    let fee_mode = resolve_fee_mode(passkey_sig);

    // Quote the fee from the fee manager before settlement.
    // This keeps fee calculation centralized in the fee manager and allows
    // the wallet to react to the returned policy decision.
    let decision: FeeDecision = env.invoke_contract(
        &fee_manager,
        &Symbol::new(env, "quote_transaction_fee"),
        vec![
            env,
            wallet.clone().into_val(env),
            tx_asset.into_val(env),
            tx_amount.into_val(env),
        ],
    );

    match decision {
        FeeDecision::CollectNow(data) => {
            // Base fee is used for protocol accounting and deferred-fee tracking.
            // If this call is not backed by a fresh passkey signature, do not add
            // a new current transaction fee.
            let added_base_fee = match fee_mode {
                FeeMode::ChargeCurrentFee => data.added_fee_in_base,
                FeeMode::ExistingBalanceOnly => 0,
            };
            // Asset fee is the converted amount that will actually be collected
            // from the wallet in the fee asset.
            let added_asset_fee = match fee_mode {
                FeeMode::ChargeCurrentFee => data.added_fee_in_asset,
                FeeMode::ExistingBalanceOnly => 0,
            };
            let total_fee = data
                .previous_deferred_fee_in_asset
                .checked_add(added_asset_fee)
                .ok_or(WalletError::InvalidAmount)?;

            // Authorize fee collection before settlement.
            //
            // This must authorize the actual fee-asset amount that the fee manager
            // will transfer from the wallet.
            __fee_deep_auth(env, data.clone().fee_asset, total_fee);

            let _: Val = env.invoke_contract(
                &fee_manager,
                &Symbol::new(env, "settle_wallet_fee"),
                vec![
                    env,
                    wallet.clone().into_val(env),
                    wallet.clone().into_val(env),
                    data.fee_asset.into_val(env),
                    added_base_fee.into_val(env),
                ],
            );
        }

        FeeDecision::Defer(data) => {
            // If the transaction is passkey-authorized, record the current
            // transaction fee as deferred protocol debt.
            //
            // If this is an existing-balance-only path, no new fee is added.
            if let FeeMode::ChargeCurrentFee = fee_mode {
                let _: Val = env.invoke_contract(
                    &fee_manager,
                    &Symbol::new(env, "update_wallet_deferred_fee"),
                    vec![
                        env,
                        wallet.clone().into_val(env),
                        data.added_base_fee.into_val(env),
                    ],
                );
            }
        }

        FeeDecision::CannotProceed(_) => {
            // The fee manager rejected the transaction because the wallet cannot
            // defer more fees under the configured protocol policy.
            return Err(WalletError::MaxDeferredFeeExceeded);
        }
    }

    Ok(())
}
