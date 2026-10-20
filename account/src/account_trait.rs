use soroban_sdk::{Address, BytesN, Env, Vec};

use socketfi_shared::{
    account_error::AccountError,
    key_types::{
        AccountSigner, AuthBindings, BindingChangeResult, BindingType, BlsKeyWithPoP, BlsSignature,
        EvmSignature, GuardianInfo, OwnerSignature, PasskeySignature,
    },
};

use crate::session_policy::{SessionPolicy, SessionPolicyInput};

/// Public interface for a SocketFi smart account.
pub trait AccountTrait {
    /// Initializes the account with exactly one owner authentication method,
    /// guardian recovery keys, deployment metadata, and initial account state.
    /// `rpid_hash` must be present even for an initial Stellar or EVM signer;
    /// its optional encoding is retained for ABI compatibility.
    // Preserve the deployed constructor ABI.
    #[allow(clippy::too_many_arguments)]
    fn __constructor(
        env: Env,
        challenge: BytesN<32>,
        passkey: Option<BytesN<65>>,
        passkey_sig: Option<PasskeySignature>,
        rpid_hash: Option<BytesN<32>>,
        stellar_signer: Option<BytesN<32>>,
        stellar_address: Option<Address>,
        evm_signer: Option<BytesN<20>>,
        evm_sig: Option<EvmSignature>,
        bls_keys_pop: Vec<BlsKeyWithPoP>,
        guardians: Vec<Address>,
        wasm_hash: BytesN<32>,
        factory: Address,
    ) -> Result<(), AccountError>;

    /// Adds a missing signer type after every current binding approves and the
    /// candidate signer proves possession.
    fn add_binding(
        env: Env,
        new_signer: AccountSigner,
        approvals: Vec<OwnerSignature>,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError>;

    /// Rotates one binding to a new signer of the same type. The binding being
    /// rotated must approve the operation and the replacement proves possession.
    fn rotate_binding(
        env: Env,
        new_signer: AccountSigner,
        approval: OwnerSignature,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError>;

    /// Removes a binding only when that binding approves and another binding
    /// remains active.
    fn remove_binding(
        env: Env,
        binding_type: BindingType,
        approval: OwnerSignature,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError>;

    /// Replaces one inaccessible binding when the other two active binding types
    /// both approve and the replacement proves possession.
    fn recover_binding_with_bindings(
        env: Env,
        new_signer: AccountSigner,
        approvals: Vec<OwnerSignature>,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError>;

    /// Replaces one binding through the independent BLS recovery authority.
    fn recover_binding_bls(
        env: Env,
        new_signer: AccountSigner,
        recovery_signature: BlsSignature,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError>;

    /// Creates a delegated session policy.
    ///
    /// Returns the generated policy identifier.
    fn create_session(
        env: Env,
        input: SessionPolicyInput,
        delegate_pop: BytesN<64>,
    ) -> Result<BytesN<32>, AccountError>;

    /// Revokes a session policy by identifier.
    fn revoke_session(env: Env, policy_id: BytesN<32>) -> Result<(), AccountError>;

    /// Invalidates all existing sessions by advancing the session epoch.
    ///
    /// Returns the new session epoch.
    fn revoke_all_sessions(env: Env) -> Result<u64, AccountError>;

    /// Upgrades the account to the latest approved contract WASM.
    fn migrate(
        env: Env,
        approvals: Vec<OwnerSignature>,
        live_until_ledger: u32,
    ) -> Result<(), AccountError>;

    /// Immediately pauses the account when authorized by a guardian.
    fn pause(env: Env, guardian: Address) -> Result<(), AccountError>;

    /// Records guardian approval for unpausing the account.
    fn approve_unpause(env: Env, guardian: Address) -> Result<(), AccountError>;

    /// Resumes account activity after owner authentication and guardian approval.
    fn unpause(env: Env) -> Result<(), AccountError>;

    /// Adds a guardian to the account.
    fn add_guardian(env: Env, guardian: Address) -> Result<(), AccountError>;

    /// Begins the delayed removal of a guardian.
    fn schedule_guardian_removal(env: Env, guardian: Address) -> Result<(), AccountError>;

    /// Completes a previously scheduled guardian removal.
    fn finalize_guardian_removal(env: Env, guardian: Address) -> Result<(), AccountError>;

    /// Returns whether the account is paused.
    fn is_paused(env: Env) -> bool;

    /// Returns a session policy by identifier.
    fn get_session(env: Env, policy_id: BytesN<32>) -> Option<SessionPolicy>;
    /// Returns every active owner binding slot.
    fn get_bindings(env: Env) -> AuthBindings;
    /// Returns the account authentication-configuration nonce.
    fn get_auth_config_nonce(env: Env) -> u64;
    /// Returns the current global session epoch.
    fn get_session_epoch(env: Env) -> u64;
    /// Returns the complete guardian list, including pending removals.
    fn get_guardians(env: Env) -> Vec<GuardianInfo>;
    /// Returns the approved target WASM and the exact migration-approval
    /// challenge for the current account configuration nonce.
    fn get_migration_challenge(
        env: Env,
        live_until_ledger: u32,
    ) -> Result<(BytesN<32>, BytesN<32>), AccountError>;
    /// Returns the currently registered passkey.
    fn get_passkey(env: Env) -> Option<BytesN<65>>;
    /// Returns whether migration is required and the target WASM hash.
    fn get_migration_required(env: Env) -> Result<(bool, Option<BytesN<32>>), AccountError>;
    /// Returns the factory contract address.
    fn get_factory(env: Env) -> Option<Address>;
}
