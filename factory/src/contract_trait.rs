use socketfi_webauthn::wallet_error::WalletError;
use soroban_sdk::{Address, BytesN, Env, String, Symbol, Vec};
use upgrade::errors::UpgradeError;

use crate::data::{BlsKeyWithPoP, PasskeyWithPoP};

/// Public interface for the factory contract.
///
/// Notes:
/// - Covers wallet creation, admin config, and upgrade governance.
pub trait FactoryTrait {
    // initialization

    /// Initialize factory state and dependencies.
    ///
    /// Notes:
    /// - Sets admin, dependencies, and wallet wasm version.
    /// - Intended to run once.
    fn __constructor(
        e: Env,
        admin: Address,
        registry: Address,
        social_router: Address,
        fee_manager: Address,
        rpid: String,
        wasm: BytesN<32>,
    ) -> Result<(), UpgradeError>;

    // wallet creation

    /// Deploy a new wallet instance.
    ///
    /// Notes:
    /// - Uses current wallet wasm version.
    /// - Returns deployed wallet address.
    fn create_wallet(
        e: Env,
        passkey_pop: PasskeyWithPoP,
        bls_keys_pop: Vec<BlsKeyWithPoP>,
        nonce: BytesN<32>,
        network: Symbol,
    ) -> Result<Address, WalletError>;

    // read-only getters

    /// Get current wallet wasm version.
    fn get_wallet_version(e: Env) -> Option<BytesN<32>>;

    ///Canonical proof-of-possession challenge salt
    fn get_pop_challenge(
        e: Env,
        nonce: BytesN<32>,
        network: Symbol,
    ) -> Result<BytesN<32>, WalletError>;

    /// Get admin address.
    fn get_admin(e: Env) -> Option<Address>;

    /// Get registry address.
    fn get_registry(e: Env) -> Option<Address>;

    /// Get fee manager address.
    fn get_fee_manager(e: Env) -> Option<Address>;

    // admin configuration updates

    /// Update admin.
    ///
    /// Notes:
    /// - Changes control over privileged actions.
    fn update_admin(e: Env, new_admin: Address);

    /// Update registry dependency.
    ///
    /// Notes:
    /// - Affects future wallet deployments.
    fn update_registry(e: Env, registry: Address);

    /// Update social router dependency.
    ///
    /// Notes:
    /// - Affects future wallet deployments.
    fn update_social_router(e: Env, social_router: Address);

    /// Update fee manager dependency.
    ///
    /// Notes:
    /// - Affects future wallet deployments.
    fn update_fee_manager(e: Env, fee_manager: Address);

    // upgrade governance

    /// Execute approved upgrade.
    ///
    /// Notes:
    /// - Applies new version state.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError>;

    /// Create upgrade proposal.
    ///
    /// Notes:
    /// - Starts governance flow for new version.
    fn propose_upgrade(
        e: Env,
        proposal_type: String,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), UpgradeError>;

    /// Add governance voter.
    fn add_voter(e: Env, voter: Address);

    /// Remove governance voter.
    fn remove_voter(e: Env, voter: Address);

    /// Cast vote on proposal.
    ///
    /// Notes:
    /// - Records voter approval.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError>;

    /// Cancel active proposal.
    fn cancel_proposal(e: Env) -> Result<(), UpgradeError>;
}
