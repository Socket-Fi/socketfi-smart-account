use socketfi_shared::{
    key_types::{BlsKeyWithPoP, PasskeySignature},
    wallet_error::WalletError,
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

    // wallet creation

    fn create_wallet(
        e: Env,
        passkey: BytesN<65>,
        passkey_sig: PasskeySignature,
        bls_keys_pop: Vec<BlsKeyWithPoP>,
        nonce: BytesN<32>,
        network: Symbol,
        guardians: Vec<Address>,
    ) -> Result<Address, WalletError>;

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

    /// Get current wallet wasm version.
    fn get_wallet_wasm_hash(e: Env) -> Option<BytesN<32>>;

    ///Canonical proof-of-possession challenge salt
    fn get_pop_challenge(
        e: Env,
        nonce: BytesN<32>,
        network: Symbol,
    ) -> Result<BytesN<32>, WalletError>;

    /// Get admin address.
    fn get_admin(e: Env) -> Option<Address>;
}
