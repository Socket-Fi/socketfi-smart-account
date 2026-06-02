use socketfi_shared::tokens::{read_allowance_expiration, read_limit};
use socketfi_webauthn::wallet_error::WalletError;
use soroban_sdk::{
    auth::{ContractContext, InvokerContractAuthEntry, SubContractInvocation},
    vec, Address, Env, FromVal, IntoVal, Map, String, Symbol, Val, Vec,
};

use socketfi_access::access::read_fee_manager;

// use crate::fee_handler::handle_transaction_fee;

fn require_args_len(args: &Vec<Val>, expected: u32) -> Result<(), WalletError> {
    if args.len() != expected {
        return Err(WalletError::InvalidInvokeArgs);
    }

    Ok(())
}

/// Validates token-related dapp_invoke and its deep auth calls against configured spend limits.
///
/// Only balance-reducing or allowance-creating operations are gated:
/// - transfer(from, to, amount)
/// - approve(from, spender, amount, expiration_ledger)
/// - burn(from, amount)
///
/// Non-token functions bypass validation.
///
/// Notes:
/// - `approve` is intentionally treated like a spend action because it
///   creates future spending capability.
/// - `transfer_from` and `burn_from` are excluded because they execute
///   previously approved allowances and are bounded by approval.
/// - Limits are enforced per invocation only (not cumulative usage).

pub fn validate_limit(
    e: &Env,
    asset: Address,
    func: Symbol,
    args: Vec<Val>,
) -> Result<(), WalletError> {
    let transfer = Symbol::new(e, "transfer");
    let approve = Symbol::new(e, "approve");
    let burn = Symbol::new(e, "burn");

    let amount_index: Option<u32> = if func == transfer {
        require_args_len(&args, 3)?;
        Some(2)
    } else if func == approve {
        require_args_len(&args, 4)?;

        //check allowance expiration
        let expiration: u32 = u32::from_val(e, &args.get_unchecked(3));

        if expiration > read_allowance_expiration(e) {
            return Err(WalletError::InvalidExpiration);
        }

        Some(2)
    } else if func == burn {
        require_args_len(&args, 2)?;
        Some(1)
    } else {
        None
    };

    let Some(index) = amount_index else {
        return Ok(());
    };

    let amount: i128 = i128::from_val(e, &args.get_unchecked(index));

    if amount < 0 {
        return Err(WalletError::InvalidAmount);
    }

    if let Some(limit) = read_limit(e, asset) {
        if amount > limit {
            return Err(WalletError::ExceedMaxAllowance);
        }
    }

    Ok(())
}

/// Build and register deep auth entries for downstream contract invocations.
///
/// Notes:
/// - Expects each map entry to describe one downstream contract call.
/// - Each auth map should contain:
///   - `contract`: target contract address
///   - `func`: target function symbol
///   - `args`: optional invocation args
/// - Missing `contract` or `func` returns an error.
/// - Registers all collected auth entries under the current contract context.
pub fn dapp_invoke_auth(e: &Env, auth_vec: Vec<Map<String, Val>>) -> Result<(), WalletError> {
    let len = auth_vec.len();
    let mut auth_entries: Vec<InvokerContractAuthEntry> = Vec::new(&e);

    for i in 0..len {
        // Read one auth descriptor from the provided vector.
        let auth_map = auth_vec.get_unchecked(i);

        // Parse optional downstream invocation arguments.
        // If omitted, an empty argument vector is used.
        let args: Vec<Val> = if let Some(val) = auth_map.get(String::from_str(e, "args")) {
            Vec::from_val(e, &val)
        } else {
            Vec::new(e)
        };

        // Parse the downstream target contract.
        // This field is required for building the auth entry.
        let contract_id: Address = if let Some(val) = auth_map.get(String::from_str(&e, "contract"))
        {
            Address::from_val(e, &val)
        } else {
            return Err(WalletError::InvalidInvokeContract);
        };

        // Parse the downstream target function.
        // This field is required for building the auth entry.
        let func: Symbol = if let Some(val) = auth_map.get(String::from_str(&e, "func")) {
            Symbol::from_val(e, &val)
        } else {
            return Err(WalletError::InvalidInvokeFunction);
        };

        validate_limit(e, contract_id.clone(), func.clone(), args.clone())?;

        // Build one deep auth entry authorizing the current contract
        // to perform the described downstream contract invocation.
        let auth_entry = InvokerContractAuthEntry::Contract(SubContractInvocation {
            context: ContractContext {
                contract: contract_id,
                fn_name: func,
                args: args.into_val(e),
            },
            sub_invocations: vec![&e],
        });

        auth_entries.push_back(auth_entry);
    }

    // Register all constructed deep auth entries for the current contract.
    e.authorize_as_current_contract(auth_entries);
    Ok(())
}

/// Register deep auth for fee payment transfer to the fee manager.
///
/// Notes:
/// - Builds authorization for a token `transfer` call from the current
///   contract to the configured fee manager.
/// - Used to allow fee collection during fee-manager-driven flows.
/// - Assumes fee manager configuration exists.
/// - Current implementation uses `unwrap()` when reading the fee manager,
///   so missing configuration would panic.
pub fn fee_deep_auth(e: &Env, tx_asset: Address, total_fee: i128) {
    // Resolve the configured fee manager address as the fee recipient.
    let to = read_fee_manager(&e).unwrap();

    // Authorize the current contract to invoke token transfer
    // for the fee amount to the fee manager contract.
    e.authorize_as_current_contract(vec![
        &e,
        InvokerContractAuthEntry::Contract(SubContractInvocation {
            context: ContractContext {
                contract: tx_asset,
                fn_name: Symbol::new(&e, "transfer"),
                args: (e.current_contract_address(), to, total_fee).into_val(e),
            },
            sub_invocations: vec![&e],
        }),
    ]);
}
