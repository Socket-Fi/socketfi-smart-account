use socketfi_shared::{
    account_error::AccountError,
    key_types::{BlsKeyWithPoP, EvmSignature, PasskeySignature},
};
use soroban_sdk::{Address, BytesN, Env, String, Symbol, Vec};
use upgrade::errors::UpgradeError;

pub trait FactoryTrait {
    // Initialize factory state and dependencies.
    fn __constructor(
        e: Env,
        admin: Address,
        rpid: String,
        wasm: BytesN<32>,
    ) -> Result<(), UpgradeError>;

    // account creation

    // Preserve the public creation ABI consumed by SDKs and clients.
    #[allow(clippy::too_many_arguments)]
    fn create_account(
        e: Env,
        passkey: Option<BytesN<65>>,
        passkey_sig: Option<PasskeySignature>,
        stellar_signer: Option<BytesN<32>>,
        stellar_address: Option<Address>,
        evm_signer: Option<BytesN<20>>,
        evm_sig: Option<EvmSignature>,

        bls_keys_pop: Vec<BlsKeyWithPoP>,
        nonce: BytesN<32>,
        network: Symbol,
        guardians: Vec<Address>,
    ) -> Result<Address, AccountError>;

    // Update admin.
    fn update_admin(e: Env, new_admin: Address);

    // Create upgrade proposal.
    fn propose_upgrade(
        e: Env,
        proposal_type: String,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), UpgradeError>;

    // Cast vote on proposal.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError>;
    // - Applies new version state.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError>;

    // Cancel active proposal.
    fn cancel_proposal(e: Env) -> Result<(), UpgradeError>;

    /// Add governance voter.
    fn add_voter(e: Env, voter: Address) -> Result<(), UpgradeError>;

    /// Remove governance voter.
    fn remove_voter(e: Env, voter: Address) -> Result<(), UpgradeError>;

    /// Get current account wasm version.
    fn get_latest_account_wasm(e: Env) -> Result<BytesN<32>, UpgradeError>;

    ///Canonical proof-of-possession challenge salt
    fn get_pop_challenge(
        e: Env,
        nonce: BytesN<32>,
        network: Symbol,
    ) -> Result<BytesN<32>, AccountError>;

    /// Get admin address.
    fn get_admin(e: Env) -> Option<Address>;
}
