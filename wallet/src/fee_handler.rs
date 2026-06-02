use socketfi_access::access::read_fee_manager;
use socketfi_shared::fee_types::FeePreference;
use socketfi_webauthn::wallet_error::WalletError;
use soroban_sdk::{vec, Env, IntoVal, Symbol, Val};

use crate::invocation_auth::fee_deep_auth;

// Handles protocol fee accounting for wallet transactions.
//
// The wallet asks the fee manager whether the current transaction would
// require immediate fee collection. If the fee manager returns a collect-now
// amount, the wallet authorizes the fee token transfer as the current contract
// before invoking the fee manager's execution handler.
//
// Flow:
// - If `fee_pref` is Some:
//     The fee manager may collect the wallet's existing deferred fee plus the
//     current transaction fee in the selected fee asset, capped by max_total_fee.
// - If `fee_pref` is None:
//     No fee transfer authorization is needed. The fee manager will defer the
//     current transaction fee if the wallet remains within the deferred limit.
// - If fee handling cannot proceed:
//     The fee manager's execution handler will return an error and the wallet
//     transaction will fail.
//
// Important:
// Fee authorization must be done in fee-asset units, not base-fee units.
// The wallet only authorizes the exact total fee amount returned by
// `get_collect_now_fee_amount`.
pub fn handle_transaction_fee(
    env: &Env,
    fee_pref: Option<FeePreference>,
) -> Result<(), WalletError> {
    let wallet = env.current_contract_address();
    let fee_manager = read_fee_manager(env).ok_or(WalletError::FeeManagerNotFound)?;

    let collect_now_fee: Option<i128> = env.invoke_contract(
        &fee_manager,
        &Symbol::new(env, "get_collect_now_fee_amount"),
        vec![
            env,
            wallet.clone().into_val(env),
            fee_pref.clone().into_val(env),
        ],
    );

    if let Some(total_fee) = collect_now_fee {
        if let Some(pref) = fee_pref.clone() {
            fee_deep_auth(env, pref.asset, total_fee);
        }
    }

    let _: Val = env.invoke_contract(
        &fee_manager,
        &Symbol::new(env, "handle_transaction_fee"),
        vec![env, wallet.into_val(env), fee_pref.into_val(env)],
    );

    Ok(())
}
