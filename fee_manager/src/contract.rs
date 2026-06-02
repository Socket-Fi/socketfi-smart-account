use soroban_sdk::{contract, contractimpl, token, Address, BytesN, Env, String, Vec};

use crate::contract_trait::FeeManagerTrait;
use crate::errors::ContractError;
use crate::fees::{
    convert_base_to_asset, delete_fee_asset_rate, read_base_fee, read_deferred_fee,
    read_fee_asset_rate, read_max_deferred_fee, write_base_fee, write_deferred_fee,
    write_fee_asset_rate, write_max_deferred_fee,
};

use socketfi_access::access::{authenticate_admin, read_admin, write_admin};
use socketfi_shared::{
    events,
    fee_types::{
        CannotProceedData, CannotProceedReason, CollectNowData, DeferData, FeeDecision,
        FeePreference,
    },
    tokens::{
        read_is_supported_asset, read_supported_assets, send_asset, take_asset, write_add_asset,
        write_remove_asset,
    },
};
use upgrade::{
    cancel_upgrade_proposal, create_upgrade_proposal, errors::UpgradeError, execute_upgrade,
    upgrade_add_voter, upgrade_remove_voter, write_cast_vote,
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
        if base_fee <= 0 || max_deferred_fee < base_fee {
            return Err(ContractError::InvalidFeeConfig);
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
        let max_deferred = read_max_deferred_fee(&e)?;

        if fee <= 0 || fee > max_deferred {
            return Err(ContractError::InvalidFeeConfig);
        }

        authenticate_admin(&e);
        write_base_fee(&e, fee);
        Ok(())
    }

    fn get_base_fee(e: Env) -> Result<i128, ContractError> {
        read_base_fee(&e)
    }

    fn set_max_deferred_fee(e: Env, fee: i128) -> Result<(), ContractError> {
        let base_fee = read_base_fee(&e)?;

        if base_fee <= 0 || fee < base_fee {
            return Err(ContractError::InvalidFeeConfig);
        }

        authenticate_admin(&e);

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
            return Err(ContractError::UnsupportedFeeAsset);
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
    // 3. If no fee preference is provided:
    //      → attempt deferred fee handling
    //
    // 4. If deferred balance would exceed the configured limit:
    //      → return CannotProceed
    //
    // 5. If a fee preference is provided:
    //      → validate the fee asset and maximum allowed fee
    //      → convert total fee once into the selected asset
    //      → return CollectNow if fee is within the user's cap
    //
    // 6. Otherwise:
    //      → return CannotProceed

    fn quote_transaction_fee(
        e: Env,
        wallet: Address,
        fee_pref: Option<FeePreference>,
    ) -> Result<FeeDecision, ContractError> {
        let base_fee = read_base_fee(&e)?;
        let max_deferred_fee = read_max_deferred_fee(&e)?;

        if base_fee <= 0 || max_deferred_fee < base_fee {
            return Err(ContractError::InvalidFeeConfig);
        }

        let deferred_fee_base = read_deferred_fee(&e, &wallet);

        if deferred_fee_base < 0 {
            return Err(ContractError::InvalidDeferredFee);
        }

        let total_fee_base = deferred_fee_base
            .checked_add(base_fee)
            .ok_or(ContractError::MathOverflow)?;

        match fee_pref {
            None => {
                if total_fee_base > max_deferred_fee {
                    return Ok(FeeDecision::CannotProceed(CannotProceedData {
                        reason: CannotProceedReason::MaxDeferredFeeExceeded,
                        fee_asset: None,
                        total_fee_in_base: total_fee_base,
                        total_fee_in_asset: None,
                        max_total_fee: None,
                        max_deferred_fee,
                    }));
                }

                Ok(FeeDecision::Defer(DeferData {
                    updated_deferred_fee: total_fee_base,
                    max_deferred_fee,
                }))
            }

            Some(pref) => {
                if pref.max_total_fee <= 0 {
                    return Ok(FeeDecision::CannotProceed(CannotProceedData {
                        reason: CannotProceedReason::InvalidMaxTotalFee,
                        fee_asset: Some(pref.asset),
                        total_fee_in_base: total_fee_base,
                        total_fee_in_asset: None,
                        max_total_fee: Some(pref.max_total_fee),
                        max_deferred_fee,
                    }));
                }

                if !read_is_supported_asset(&e, pref.asset.clone()) {
                    return Ok(FeeDecision::CannotProceed(CannotProceedData {
                        reason: CannotProceedReason::UnsupportedFeeAsset,
                        fee_asset: Some(pref.asset),
                        total_fee_in_base: total_fee_base,
                        total_fee_in_asset: None,
                        max_total_fee: Some(pref.max_total_fee),
                        max_deferred_fee,
                    }));
                }

                let rate = read_fee_asset_rate(&e, &pref.asset)?;
                let decimals: u32 = token::Client::new(&e, &pref.asset).decimals();

                let total_fee_in_asset = convert_base_to_asset(total_fee_base, rate, decimals)?;

                if total_fee_in_asset > pref.max_total_fee {
                    return Ok(FeeDecision::CannotProceed(CannotProceedData {
                        reason: CannotProceedReason::FeeExceedsMaximum,
                        fee_asset: Some(pref.asset),
                        total_fee_in_base: total_fee_base,
                        total_fee_in_asset: Some(total_fee_in_asset),
                        max_total_fee: Some(pref.max_total_fee),
                        max_deferred_fee,
                    }));
                }

                Ok(FeeDecision::CollectNow(CollectNowData {
                    fee_asset: pref.asset,
                    total_fee_in_base: total_fee_base,
                    total_fee_in_asset,
                    max_total_fee: pref.max_total_fee,
                }))
            }
        }
    }

    /// Returns the immediate fee amount that would be collected for a wallet
    /// transaction if the current fee decision resolves to `CollectNow`.
    ///
    /// Returns:
    /// - `Some(amount)` when the transaction fee would be collected immediately.
    /// - `None` when the fee would instead be deferred or cannot proceed.
    ///
    /// Notes:
    /// - This helper is primarily used by the wallet contract to pre-authorize
    ///   fee token transfers before calling `handle_transaction_fee`.
    fn get_collect_now_fee_amount(
        e: Env,
        wallet: Address,
        fee_pref: Option<FeePreference>,
    ) -> Option<i128> {
        let decision = Self::quote_transaction_fee(e, wallet, fee_pref).ok()?;

        match decision {
            FeeDecision::CollectNow(data) => Some(data.total_fee_in_asset),

            _ => None,
        }
    }

    /// Handles protocol fee processing for wallet transactions.
    ///
    /// Flow:
    /// - Calls `quote_transaction_fee` to determine how the fee should be handled.
    /// - If fee collection is requested and valid:
    ///     → collects deferred fee + current transaction fee immediately.
    /// - If no fee preference is provided:
    ///     → defers the current transaction fee.
    /// - If fee handling cannot proceed:
    ///     → returns a corresponding contract error.
    ///
    /// Notes:
    /// - This function is the single execution path for transaction fee handling.
    /// - All wallet transaction entrypoints should call this function.
    /// - Deferred fee state is updated atomically.
    /// - Fee conversion is performed exactly once to avoid rounding mismatch.

    fn handle_transaction_fee(
        e: Env,
        wallet: Address,
        fee_pref: Option<FeePreference>,
    ) -> Result<(), ContractError> {
        wallet.require_auth();

        let decision = Self::quote_transaction_fee(e.clone(), wallet.clone(), fee_pref)?;

        match decision {
            FeeDecision::CollectNow(data) => {
                take_asset(&e, &wallet, &data.fee_asset, data.total_fee_in_asset);

                write_deferred_fee(&e, &wallet, 0);

                Ok(())
            }

            FeeDecision::Defer(data) => {
                write_deferred_fee(&e, &wallet, data.updated_deferred_fee);

                Ok(())
            }

            FeeDecision::CannotProceed(data) => match data.reason {
                CannotProceedReason::UnsupportedFeeAsset => Err(ContractError::UnsupportedFeeAsset),
                CannotProceedReason::FeeExceedsMaximum => Err(ContractError::FeeExceedsMaximum),
                CannotProceedReason::MaxDeferredFeeExceeded => {
                    Err(ContractError::MaxDeferredFeeExceeded)
                }
                CannotProceedReason::InvalidMaxTotalFee => Err(ContractError::InvalidMaxTotalFee),
            },
        }
    }

    /// Settles a wallet's existing deferred protocol fee balance.
    ///
    /// Security:
    /// - `payer` authorizes payment using the selected fee asset.
    /// - Anyone may settle fees on behalf of a wallet.
    ///
    /// Notes:
    /// - This function settles only existing deferred fees.
    /// - It does not add the current transaction fee.
    /// - Fee conversion is performed exactly once.
    /// - Deferred fee balance is cleared after successful settlement.
    fn settle_wallet_fee(
        e: Env,
        payer: Address,
        wallet: Address,
        fee_pref: FeePreference,
    ) -> Result<(), ContractError> {
        payer.require_auth();

        if fee_pref.max_total_fee <= 0 {
            return Err(ContractError::InvalidMaxTotalFee);
        }

        if !read_is_supported_asset(&e, fee_pref.asset.clone()) {
            return Err(ContractError::UnsupportedFeeAsset);
        }

        let deferred_fee_base = read_deferred_fee(&e, &wallet);

        if deferred_fee_base < 0 {
            return Err(ContractError::InvalidDeferredFee);
        }

        if deferred_fee_base == 0 {
            return Ok(());
        }

        let rate = read_fee_asset_rate(&e, &fee_pref.asset)?;
        let decimals: u32 = token::Client::new(&e, &fee_pref.asset).decimals();

        let fee_in_asset = convert_base_to_asset(deferred_fee_base, rate, decimals)?;

        if fee_in_asset > fee_pref.max_total_fee {
            return Err(ContractError::FeeExceedsMaximum);
        }

        take_asset(&e, &payer, &fee_pref.asset, fee_in_asset);

        write_deferred_fee(&e, &wallet, 0);

        Ok(())
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
            return Err(ContractError::UnsupportedFeeAsset);
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
    /// Execute approved upgrade.
    ///
    /// Notes:
    /// - Admin only.
    /// - Applies current passed proposal.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError> {
        authenticate_admin(&e);
        execute_upgrade(&e)
    }

    /// Create upgrade proposal.
    ///
    /// Notes:
    /// - Admin only.
    /// - Starts governance flow for new wasm hash.
    fn propose_upgrade(
        e: Env,
        proposal_type: String,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        create_upgrade_proposal(&e, proposal_type, &new_wasm_hash)
    }

    /// Add governance voter.
    ///
    /// Notes:
    /// - Admin only.
    fn add_voter(e: Env, voter: Address) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        upgrade_add_voter(&e, &voter)?;

        events::AddVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    /// Remove governance voter.
    ///
    /// Notes:
    /// - Admin only.
    fn remove_voter(e: Env, voter: Address) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        upgrade_remove_voter(&e, &voter)?;

        events::RemoveVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    /// Cast vote on active proposal.
    ///
    /// Notes:
    /// - Voter must authorize.
    /// - Records approval for supplied hash.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError> {
        voter.require_auth();
        write_cast_vote(&e, &voter, &wasm_hash)?;
        Ok(())
    }

    /// Cancel active proposal.
    ///
    /// Notes:
    /// - Admin only.
    fn cancel_proposal(e: Env) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        cancel_upgrade_proposal(&e)
    }
}
