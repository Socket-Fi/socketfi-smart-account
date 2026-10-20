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
        network: Symbol,
        factory_wasm: BytesN<32>,
        account_wasm: BytesN<32>,
        voters: Vec<Address>,
    ) -> Result<(), UpgradeError>;

    // account creation

    // The V2 creation ABI includes the signed expiry as its final argument.
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
        live_until_ledger: u32,
    ) -> Result<Address, AccountError>;

    // Update admin.
    fn update_admin(
        e: Env,
        new_admin: Address,
        approvals: Vec<Address>,
    ) -> Result<(), UpgradeError>;

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
    fn cancel_proposal(e: Env, approvals: Vec<Address>) -> Result<(), UpgradeError>;

    /// Add governance voter.
    fn add_voter(e: Env, voter: Address, approvals: Vec<Address>) -> Result<(), UpgradeError>;

    /// Remove governance voter.
    fn remove_voter(e: Env, voter: Address, approvals: Vec<Address>) -> Result<(), UpgradeError>;

    /// Get current account wasm version.
    fn get_latest_account_wasm(e: Env) -> Result<BytesN<32>, UpgradeError>;

    ///Canonical proof-of-possession challenge salt
    #[allow(clippy::too_many_arguments)]
    fn get_pop_challenge(
        e: Env,
        passkey: Option<BytesN<65>>,
        stellar_signer: Option<BytesN<32>>,
        evm_signer: Option<BytesN<20>>,
        bls_keys: Vec<BytesN<96>>,
        nonce: BytesN<32>,
        network: Symbol,
        guardians: Vec<Address>,
        live_until_ledger: u32,
    ) -> Result<BytesN<32>, AccountError>;

    /// Returns whether this Factory canonically deployed the account.
    fn is_registered_account(e: Env, account: Address) -> bool;

    /// Returns the network configured for this Factory deployment.
    fn get_network(e: Env) -> Option<Symbol>;

    /// Get admin address.
    fn get_admin(e: Env) -> Option<Address>;
}
