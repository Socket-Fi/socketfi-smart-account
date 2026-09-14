use soroban_sdk::{Address, BytesN, Env, Vec};

use socketfi_shared::{
    account_error::AccountError,
    key_types::{AccountSigner, BlsKeyWithPoP, BlsSignature, EvmSignature, PasskeySignature},
};

use crate::session_policy::{SessionPolicy, SessionPolicyInput};

/// Public interface for a SocketFi smart account.
pub trait AccountTrait {
    /// Initializes the account with at least one owner authentication method,
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

    /// Replaces the current owner signer and invalidates existing sessions.
    ///
    /// Returns the new session epoch.
    fn rotate_account(
        env: Env,
        new_signer: AccountSigner,
        live_until_ledger: u32,
    ) -> Result<u64, AccountError>;

    /// Recovers the account using guardian authorization, installs a new owner,
    /// and invalidates existing sessions.
    ///
    /// Returns the new session epoch.
    fn recover_account(
        env: Env,
        new_signer: AccountSigner,
        recovery_signature: BlsSignature,
        live_until_ledger: u32,
    ) -> Result<u64, AccountError>;

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
    fn migrate(env: Env) -> Result<(), AccountError>;

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
    /// Returns the currently registered passkey.
    fn get_passkey(env: Env) -> Option<BytesN<65>>;
    /// Returns whether migration is required and the target WASM hash.
    fn get_migration_required(env: Env) -> (bool, Option<BytesN<32>>);
    /// Returns the factory contract address.
    fn get_factory(env: Env) -> Option<Address>;
}
