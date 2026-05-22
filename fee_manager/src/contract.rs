use socketfi_shared::events;
use socketfi_shared::tokens::send_asset;
use soroban_sdk::{contract, contractimpl, token, Address, BytesN, Env, Vec};

use crate::contract_trait::FeeManagerTrait;
use crate::errors::ContractError;
use crate::fees::{
    convert_base_to_asset, delete_fee_asset_rate, read_base_fee, read_deferred_fee,
    read_fee_asset_rate, read_max_deferred_fee, write_base_fee, write_deferred_fee,
    write_fee_asset_rate, write_max_deferred_fee,
};

use socketfi_access::access::{authenticate_admin, read_admin, write_admin};
use socketfi_shared::{
    fee_types::{CannotProceedData, CollectNowData, DeferData, FeeDecision},
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

    fn get_base_fee(e: Env) -> Result<i128, ContractError> {
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
    // Determines how protocol fees should be handled for a transaction.
    //
    // Flow:
    // 1. Read configured base fee, max deferred fee, and wallet deferred balance.
    // 2. Compute the updated fee balance:
    //      updated_fee = deferred_fee + base_fee
    // 3. If the transaction asset supports fee collection:
    //      → return CollectNow
    // 4. If the asset does not support collection and updated fee exceeds
    //    the configured deferred limit:
    //      → return CannotProceed
    // 5. Otherwise:
    //      → return Defer with the updated deferred balance
    //
    // Notes:
    // - Returned values are informational only and do not mutate state.
    // - Execution paths must enforce the returned decision.
    // - All fee values are represented in internal base fee units unless
    //   otherwise specified.
    fn quote_transaction_fee(
        e: Env,
        wallet: Address,
        tx_asset: Address,
        tx_amount: i128,
    ) -> Result<FeeDecision, ContractError> {
        if tx_amount < 0 {
            return Err(ContractError::InvalidAmount);
        }

        let base_fee = read_base_fee(&e)?;
        let max_deferred_fee = read_max_deferred_fee(&e)?;

        if base_fee < 0 || max_deferred_fee < 0 {
            return Err(ContractError::InvalidAmount);
        }

        let deferred_fee = read_deferred_fee(&e, &wallet);

        if deferred_fee < 0 {
            return Err(ContractError::InvalidAmount);
        }

        let total_fee_base = deferred_fee
            .checked_add(base_fee)
            .ok_or(ContractError::InvalidAmount)?;

        if read_is_supported_asset(&e, tx_asset.clone()) {
            let rate = read_fee_asset_rate(&e, &tx_asset)?;
            let decimals: u32 = token::Client::new(&e, &tx_asset).decimals();

            let total_fee_in_asset = convert_base_to_asset(total_fee_base, rate, decimals)?;
            let added_in_asset = convert_base_to_asset(base_fee, rate, decimals)?;
            let deferred_in_asset = convert_base_to_asset(deferred_fee, rate, decimals)?;

            let total_tx_amount = tx_amount
                .checked_add(total_fee_in_asset)
                .ok_or(ContractError::InvalidAmount)?;

            return Ok(FeeDecision::CollectNow(CollectNowData {
                fee_asset: tx_asset,
                previous_deferred_fee_in_base: deferred_fee,
                previous_deferred_fee_in_asset: deferred_in_asset,
                added_fee_in_base: base_fee,
                added_fee_in_asset: added_in_asset,
                total_in_base: total_fee_base,
                total_fee_in_asset,
                total_tx_amount,
            }));
        }

        if total_fee_base > max_deferred_fee {
            return Ok(FeeDecision::CannotProceed(CannotProceedData {
                previous_deferred_fee: deferred_fee,
                added_base_fee: base_fee,
                updated_deferred_fee: total_fee_base,
                max_deferred_fee,
                total_tx_amount: tx_amount,
            }));
        }

        Ok(FeeDecision::Defer(DeferData {
            previous_deferred_fee: deferred_fee,
            added_base_fee: base_fee,
            updated_deferred_fee: total_fee_base,
            total_tx_amount: tx_amount,
        }))
    }

    /// -------------------------------------------------------------------------
    /// Settles a wallet's accumulated deferred protocol fees.
    /// -------------------------------------------------------------------------
    /// Security model:
    /// - `payer` MUST authorize the payment.
    /// - `wallet` identifies the wallet whose deferred fee balance is being settled.
    /// - `added_base_fee` allows the caller to atomically include the current
    ///   transaction fee into settlement instead of writing deferred state first.
    /// Notes:
    /// - Passing `added_base_fee = 0` settles only existing deferred fees.
    /// - Passing `added_base_fee > 0` is intended for wallet execution flows
    ///   where the current transaction fee should be collected immediately.
    /// - Third parties are not allowed to inject additional fees.

    fn settle_wallet_fee(
        e: Env,
        payer: Address,
        wallet: Address,
        fee_asset: Address,
        added_base_fee: i128,
    ) -> Result<(), ContractError> {
        payer.require_auth();

        if added_base_fee < 0 {
            return Err(ContractError::InvalidAmount);
        }

        if added_base_fee > 0 && payer != wallet {
            return Err(ContractError::Unauthorized);
        }

        let current_base_fee = read_deferred_fee(&e, &wallet);

        if current_base_fee < 0 {
            return Err(ContractError::InvalidAmount);
        }

        let updated_base_fee = current_base_fee
            .checked_add(added_base_fee)
            .ok_or(ContractError::InvalidAmount)?;

        if updated_base_fee == 0 {
            return Ok(());
        }
        let decimals: u32 = token::Client::new(&e, &fee_asset).decimals();

        let total_fee = convert_base_to_asset(
            updated_base_fee,
            read_fee_asset_rate(&e, &fee_asset)?,
            decimals,
        )?;

        take_asset(&e, &payer, &fee_asset, total_fee);

        write_deferred_fee(&e, &wallet, 0);

        Ok(())
    }

    /// Increases the deferred fee balance for a wallet.
    ///
    /// Purpose:
    /// Allows a wallet to accumulate unpaid protocol fees in base fee units
    /// for later settlement.
    ///
    /// Security:
    /// - Only the wallet itself may authorize deferred fee increases.
    /// - The function only permits increasing the balance.
    /// - Negative or zero increments are rejected.
    /// - Overflow is rejected.
    ///
    /// Behavior:
    /// previous_deferred_fee + added_base_fee → updated_deferred_fee
    ///
    /// Notes:
    /// - This function is called when fee is deferred.
    fn update_wallet_deferred_fee(
        e: Env,
        wallet: Address,
        added_base_fee: i128,
    ) -> Result<i128, ContractError> {
        wallet.require_auth();

        if added_base_fee <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        let current_base_fee = read_deferred_fee(&e, &wallet);

        if current_base_fee < 0 {
            return Err(ContractError::InvalidAmount);
        }

        let updated_base_fee = current_base_fee
            .checked_add(added_base_fee)
            .ok_or(ContractError::InvalidAmount)?;

        write_deferred_fee(&e, &wallet, updated_base_fee);

        Ok(updated_base_fee)
    }

    // -------------------------------------------------------------------------
    // Fee Treasury Management
    // -------------------------------------------------------------------------

    /// Withdraw collected protocol fees from the fee manager.
    ///
    /// - Allows the admin to transfer accumulated fee assets out of the contract.
    ///
    /// Validation:
    /// - Caller must be admin.
    /// - Asset must be a supported fee asset.
    /// - Amount must be positive.
    /// - Withdrawal cannot exceed the contract's asset balance.
    ///
    /// Emits:
    /// - WithdrawFeeEvent(asset, amount, to)
    fn withdraw_collected_fees(
        e: Env,
        asset: Address,
        amount: i128,
        to: Address,
    ) -> Result<(), ContractError> {
        authenticate_admin(&e);

        if amount <= 0 {
            return Err(ContractError::InvalidAmount);
        }

        if !read_is_supported_asset(&e, asset.clone()) {
            return Err(ContractError::UnsupportedAsset);
        }

        let fee_balance = token::Client::new(&e, &asset).balance(&e.current_contract_address());

        if amount > fee_balance {
            return Err(ContractError::InvalidAmount);
        }

        send_asset(&e, &to, &asset, amount);

        events::WithdrawFeeEvent { asset, amount, to }.publish(&e);

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Contract Upgrade
    // -------------------------------------------------------------------------
    fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        authenticate_admin(&e);
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
