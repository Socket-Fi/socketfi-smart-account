use soroban_sdk::{Address, BytesN, Env, String, Vec};
use upgrade::errors::UpgradeError;

use crate::errors::ContractError;
use socketfi_shared::fee_types::{FeeDecision, FeePreference};

pub trait FeeManagerTrait {
    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    fn __constructor(
        e: Env,
        admin: Address,
        base_fee: i128,
        max_deferred_fee: i128,
    ) -> Result<(), ContractError>;

    // -------------------------------------------------------------------------
    // Admin Management
    // -------------------------------------------------------------------------
    fn get_admin(e: Env) -> Option<Address>;
    fn set_admin(e: Env, new_admin: Address) -> Result<(), ContractError>;

    // -------------------------------------------------------------------------
    // Base Fee Configuration
    // -------------------------------------------------------------------------
    fn set_base_fee(e: Env, fee: i128) -> Result<(), ContractError>;
    fn get_base_fee(e: Env) -> Result<i128, ContractError>;

    fn set_max_deferred_fee(e: Env, fee: i128) -> Result<(), ContractError>;
    fn get_max_deferred_fee(e: Env) -> Result<i128, ContractError>;

    // -------------------------------------------------------------------------
    // Supported Fee Assets
    // -------------------------------------------------------------------------
    fn add_supported_fee_asset(e: Env, asset: Address, rate: i128) -> Result<(), ContractError>;
    fn remove_supported_fee_asset(e: Env, asset: Address) -> Result<(), ContractError>;

    fn set_fee_asset_rate(e: Env, asset: Address, rate: i128) -> Result<(), ContractError>;

    fn is_supported_fee_asset(e: Env, asset: Address) -> bool;
    fn get_supported_fee_assets(e: Env) -> Vec<Address>;
    fn get_fee_asset_rate(e: Env, asset: Address) -> Result<i128, ContractError>;

    // -------------------------------------------------------------------------
    // Deferred Fee State
    // -------------------------------------------------------------------------
    fn get_deferred_fee(e: Env, user: Address) -> Result<i128, ContractError>;

    // -------------------------------------------------------------------------
    // Fee Logic (Core)
    // -------------------------------------------------------------------------
    // Determines whether to collect fee immediately or defer
    fn quote_transaction_fee(
        e: Env,
        wallet: Address,
        fee_pref: Option<FeePreference>,
    ) -> Result<FeeDecision, ContractError>;

    fn get_collect_now_fee_amount(
        e: Env,
        wallet: Address,
        fee_pref: Option<FeePreference>,
    ) -> Option<i128>;

    // Handles the settlement of quote_transaction_fee
    fn handle_transaction_fee(
        e: Env,
        wallet: Address,
        fee_pref: Option<FeePreference>,
    ) -> Result<(), ContractError>;
    fn settle_wallet_fee(
        e: Env,
        payer: Address,
        wallet: Address,
        fee_pref: FeePreference,
    ) -> Result<(), ContractError>;

    // -------------------------------------------------------------------------
    // Fee Treasury Management
    // -------------------------------------------------------------------------

    fn withdraw_collected_fees(
        e: Env,
        asset: Address,
        amount: i128,
        to: Address,
    ) -> Result<(), ContractError>;

    // -------------------------------------------------------------------------
    // Contract Upgrade
    // -------------------------------------------------------------------------

    /// - Applies the current passed proposal.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError>;

    /// - Starts governance flow for a new wasm hash.
    fn propose_upgrade(
        e: Env,
        proposal_type: String,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), UpgradeError>;

    /// Add governance voter.
    fn add_voter(e: Env, voter: Address) -> Result<(), UpgradeError>;

    /// Remove governance voter.
    fn remove_voter(e: Env, voter: Address) -> Result<(), UpgradeError>;

    /// - Records voter approval for the supplied hash.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError>;

    /// Cancel active proposal.
    fn cancel_proposal(e: Env) -> Result<(), UpgradeError>;
}
