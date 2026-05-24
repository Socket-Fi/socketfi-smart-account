use soroban_sdk::{Address, BytesN, Env, String, Vec};

use socketfi_shared::{registry_errors::RegistryError, registry_types::ValidatorSignature};
use upgrade::errors::UpgradeError;

/// Public interface for the identity registry contract.
///
/// Notes:
/// - Covers identity binding, user mapping, validator management,
///   admin control, and upgrade governance.
pub trait RegistryTrait {
    // initialization

    /// Initialize registry state.
    ///
    /// Notes:
    /// - Sets the initial admin.
    /// - Intended to run once.
    fn __constructor(e: Env, admin: Address) -> Result<(), UpgradeError>;

    fn add_manager(e: Env, manager: Address) -> Result<(), RegistryError>;

    fn remove_manager(e: Env, manager: Address) -> Result<(), RegistryError>;

    // identity core

    fn set_id_wallet_map(
        e: Env,
        wallet: Address,
        user_id: String,
        platform_str: String,
        signatures: Vec<ValidatorSignature>,
    ) -> Result<(), RegistryError>;

    fn remove_id_wallet_map(
        e: Env,
        user_id: String,
        platform_str: String,
    ) -> Result<(), RegistryError>;

    fn manager_remove_id_wallet_map(
        e: Env,
        user_id: String,
        platform_str: String,
        manager: Address,
    ) -> Result<(), RegistryError>;
    // validator management

    /// Add a validator public key.
    ///
    /// Notes:
    /// - Expands the set of valid identity signers.
    fn add_validator(e: Env, validator: BytesN<32>);

    /// Remove a validator public key.
    ///
    /// Notes:
    /// - Revokes validator approval for future checks.
    fn remove_validator(e: Env, validator: BytesN<32>);

    /// Return all configured validators.
    fn get_validators(e: Env) -> Vec<BytesN<32>>;

    // read APIs

    /// Resolve wallet by `(platform, user_id)`.
    ///
    /// Notes:
    /// - Returns `None` when no mapping exists.
    fn get_wallet_by_userid(
        e: Env,
        platform: String,
        user_id: String,
    ) -> Result<Option<Address>, RegistryError>;

    // admin/config

    /// Update admin.
    ///
    /// Notes:
    /// - Changes control over privileged registry actions.
    fn set_admin(e: Env, new_admin: Address);

    // upgrade governance

    /// Execute approved upgrade proposal.
    ///
    /// Notes:
    /// - Applies the current passed proposal.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError>;

    /// Create upgrade proposal.
    ///
    /// Notes:
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

    /// Cast vote on active proposal.
    ///
    /// Notes:
    /// - Records voter approval for the supplied hash.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError>;

    /// Cancel active proposal.
    fn cancel_proposal(e: Env) -> Result<(), UpgradeError>;
}
