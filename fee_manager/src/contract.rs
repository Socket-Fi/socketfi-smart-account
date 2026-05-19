use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, Vec};

use crate::contract_trait::FeeManagerTrait;
use crate::errors::ContractError;
use crate::fees::{
    convert_base_to_asset, delete_fee_asset_rate, read_base_fee, read_deferred_fee,
    read_fee_asset_rate, read_max_deferred_fee, write_base_fee, write_deferred_fee,
    write_fee_asset_rate, write_max_deferred_fee,
};

use socketfi_access::access::{authenticate_admin, read_admin, write_admin};
use socketfi_shared::{
    fee_types::{CollectNowData, DeferData, FeeDecision},
    tokens::{
        read_is_supported_asset, read_supported_assets, take_asset, write_add_asset,
        write_remove_asset,
    },
};

#[contract]
pub struct FeeManager;

#[contractimpl]
impl FeeManagerTrait for FeeManager {
    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    // Initializes the contract with:
    // - admin: contract administrator
    // - base_fee: default fee amount in base units
    // - max_deferred_fee: maximum deferred fee a user can accumulate
    fn __constructor(
        e: Env,
        admin: Address,
        base_fee: i128,
        max_deferred_fee: i128,
    ) -> Result<(), ContractError> {
        if base_fee <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        if max_deferred_fee < base_fee {
            return Err(ContractError::InvalidAmount);
        }

        write_admin(&e, &admin);
        write_base_fee(&e, base_fee);
        write_max_deferred_fee(&e, max_deferred_fee);

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Admin Management
    // -------------------------------------------------------------------------
    fn set_admin(e: Env, new_admin: Address) -> Result<(), ContractError> {
        authenticate_admin(&e);
        write_admin(&e, &new_admin);
        Ok(())
    }

    fn get_admin(e: Env) -> Option<Address> {
        read_admin(&e)
    }

    // -------------------------------------------------------------------------
    // Base Fee Configuration
    // -------------------------------------------------------------------------
    fn set_base_fee(e: Env, fee: i128) -> Result<(), ContractError> {
        authenticate_admin(&e);

        if fee <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        write_base_fee(&e, fee);
        Ok(())
    }

    fn get_base_fee(e: Env) -> Option<i128> {
        read_base_fee(&e)
    }

    fn set_max_deferred_fee(e: Env, fee: i128) -> Result<(), ContractError> {
        authenticate_admin(&e);

        if fee <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        write_max_deferred_fee(&e, fee);
        Ok(())
    }

    fn get_max_deferred_fee(e: Env) -> Result<i128, ContractError> {
        read_max_deferred_fee(&e)
    }

    // -------------------------------------------------------------------------
    // Supported Fee Assets
    // -------------------------------------------------------------------------
    // Adds an asset as a supported fee payment asset and stores its conversion rate.
    fn add_supported_fee_asset(e: Env, asset: Address, rate: i128) -> Result<(), ContractError> {
        authenticate_admin(&e);

        if rate <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        write_add_asset(&e, asset.clone());
        write_fee_asset_rate(&e, &asset, rate);

        Ok(())
    }

    // Removes an asset from the supported fee asset list and deletes its rate.
    fn remove_supported_fee_asset(e: Env, asset: Address) -> Result<(), ContractError> {
        authenticate_admin(&e);
        write_remove_asset(&e, asset.clone());
        delete_fee_asset_rate(&e, &asset);
        Ok(())
    }

    // Updates the conversion rate for a supported fee asset.
    fn set_fee_asset_rate(e: Env, asset: Address, rate: i128) -> Result<(), ContractError> {
        authenticate_admin(&e);

        if rate <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        if !read_is_supported_asset(&e, asset.clone()) {
            return Err(ContractError::UnsupportedAsset);
        }

        write_fee_asset_rate(&e, &asset, rate);
        Ok(())
    }

    fn is_supported_fee_asset(e: Env, asset: Address) -> bool {
        read_is_supported_asset(&e, asset)
    }

    fn get_supported_fee_assets(e: Env) -> Vec<Address> {
        read_supported_assets(&e)
    }

    fn get_fee_asset_rate(e: Env, asset: Address) -> Result<i128, ContractError> {
        read_fee_asset_rate(&e, &asset)
    }

    // -------------------------------------------------------------------------
    // Deferred Fee State
    // -------------------------------------------------------------------------
    // Returns the currently accumulated deferred fee for a user.
    fn get_deferred_fee(e: Env, user: Address) -> Result<i128, ContractError> {
        Ok(read_deferred_fee(&e, &user))
    }

    // -------------------------------------------------------------------------
    // Fee Quoting
    // -------------------------------------------------------------------------
    // Determines whether a fee should be collected immediately or deferred.
    //
    // Flow:
    // 1. Read the base fee, max deferred fee, and current deferred fee.
    // 2. Attempt to add current deferred fee + base fee.
    // 3. If the transaction asset is supported and conversion succeeds,
    //    return CollectNow with the computed asset-denominated fee.
    // 4. Otherwise, defer according to the existing business rules.
    fn quote_transaction_fee(
        e: Env,
        user: Address,
        tx_asset: Address,
        tx_amount: i128,
    ) -> FeeDecision {
        let base_fee = read_base_fee(&e).unwrap_or(0);
        let max_deferred_fee = read_max_deferred_fee(&e).unwrap_or(base_fee);
        let deferred_fee = read_deferred_fee(&e, &user);

        let total_fee_base = match deferred_fee.checked_add(base_fee) {
            Some(v) => v,
            None => {
                return FeeDecision::Defer(DeferData {
                    updated_deferred_fee: deferred_fee,
                    total_tx_amount: tx_amount,
                });
            }
        };

        // If the transaction asset is supported, try to collect the fee now
        // in the same asset used by the transaction.
        if read_is_supported_asset(&e, tx_asset.clone()) {
            if let Ok(rate) = read_fee_asset_rate(&e, &tx_asset) {
                if let Ok(total_fee_in_asset) = convert_base_to_asset(total_fee_base, rate) {
                    if let Some(total_tx_amount) = tx_amount.checked_add(total_fee_in_asset) {
                        return FeeDecision::CollectNow(CollectNowData {
                            fee_asset: tx_asset,
                            total_fee_in_asset,
                            total_in_base: total_fee_base,
                            total_tx_amount,
                        });
                    }
                }
            }
        }

        if total_fee_base > max_deferred_fee {
            return FeeDecision::Defer(DeferData {
                updated_deferred_fee: deferred_fee,
                total_tx_amount: tx_amount,
            });
        }

        FeeDecision::Defer(DeferData {
            updated_deferred_fee: total_fee_base,
            total_tx_amount: tx_amount,
        })
    }

    // -------------------------------------------------------------------------
    // Fee Application
    // -------------------------------------------------------------------------
    // Applies the previously quoted fee decision:
    // - CollectNow: charge asset immediately and clear deferred fee
    // - Defer: persist the updated deferred fee
    fn apply_transaction_fee(e: Env, wallet: Address, decision: FeeDecision) {
        wallet.require_auth();

        match &decision {
            FeeDecision::CollectNow(data) => {
                take_asset(&e, &wallet, &data.fee_asset, data.total_fee_in_asset);
                write_deferred_fee(&e, &wallet, 0);
            }
            FeeDecision::Defer(data) => {
                write_deferred_fee(&e, &wallet, data.updated_deferred_fee);
            }
        }
    }

    // -------------------------------------------------------------------------
    // Contract Upgrade
    // -------------------------------------------------------------------------
    fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        authenticate_admin(&e);
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
