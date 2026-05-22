use socketfi_shared::registry_errors::RegistryError;
use soroban_sdk::{Address, BytesN, Env, String, Vec};
use upgrade::errors::UpgradeError;

use crate::data::{PaymentResult, PendingPayment};

/// Public interface for the social payments router.
///
/// Notes:
/// - Covers social payments, claims, refunds, queries, admin config,
///   and upgrade governance.
pub trait SocialPaymentsTrait {
    // initialization

    /// Initialize router state.
    ///
    /// Notes:
    /// - Sets initial admin and registry.
    /// - Intended to run once.
    fn __constructor(e: Env, admin: Address, registry: Address) -> Result<(), UpgradeError>;

    // payments

    /// Pay to a social identity.
    ///
    /// Notes:
    /// - Sends directly if identity already resolves to a wallet.
    /// - Otherwise stores a pending payment for later claim.
    fn pay_to_social(
        e: Env,
        sender: Address,
        platform_str: String,
        user_id: String,
        asset: Address,
        amount: i128,
        duration: Option<u64>,
    ) -> Result<PaymentResult, RegistryError>;

    /// Claim one pending payment.
    ///
    /// Notes:
    /// - Resolves payment to claimer if claim conditions pass.
    fn claim_payment(e: Env, claimer: Address, payment_id: BytesN<32>)
        -> Result<(), RegistryError>;

    /// Claim multiple pending payments.
    ///
    /// Notes:
    /// - Processes each payment in sequence.
    /// - Fails if any claim fails.
    fn claim_payments(
        e: Env,
        claimer: Address,
        payment_ids: Vec<BytesN<32>>,
    ) -> Result<(), RegistryError>;

    /// Refund one payment.
    ///
    /// Notes:
    /// - Sender-driven refund path.
    fn refund_payment(e: Env, sender: Address, payment_id: BytesN<32>)
        -> Result<(), RegistryError>;

    /// Refund multiple payments.
    ///
    /// Notes:
    /// - Processes each refund in sequence.
    /// - Fails if any refund fails.
    fn refund_payments(
        e: Env,
        sender: Address,
        payment_ids: Vec<BytesN<32>>,
    ) -> Result<(), RegistryError>;

    // queries

    /// Get payment ids for a social identity.
    ///
    /// Notes:
    /// - Returns all payment ids indexed under `(platform, user_id)`.
    fn get_identity_payments(
        e: Env,
        platform: String,
        user_id: String,
    ) -> Result<Vec<BytesN<32>>, RegistryError>;

    /// Get payment ids created by a sender.
    fn get_sender_payments(e: Env, sender: Address) -> Vec<BytesN<32>>;

    /// Get total claimable amount for an identity and asset.
    ///
    /// Notes:
    /// - Aggregates pending claimable value for the given asset.
    fn get_claimable_total(
        e: Env,
        platform: String,
        user_id: String,
        asset: Address,
    ) -> Result<i128, RegistryError>;

    /// Get stored payment by id.
    fn get_payment(e: Env, payment_id: BytesN<32>) -> Option<PendingPayment>;

    /// Get current payment nonce.
    ///
    /// Notes:
    /// - Used in payment id generation.
    fn get_nonce(e: Env) -> u64;

    /// Get supported payment assets.
    fn get_supported_assets(e: Env) -> Vec<Address>;

    // admin

    /// Add supported asset.
    ///
    /// Notes:
    /// - Expands assets accepted by `pay_to_social`.
    fn add_supported_asset(e: Env, asset: Address);

    /// Remove supported asset.
    ///
    /// Notes:
    /// - Prevents new payments in that asset.
    fn remove_supported_asset(e: Env, asset: Address);

    /// Update admin.
    ///
    /// Notes:
    /// - Changes control over privileged router actions.
    fn set_admin(e: Env, new_admin: Address);

    // upgrade governance

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
    /// - Records voter approval for supplied hash.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError>;

    /// Execute approved upgrade proposal.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError>;

    /// Cancel active proposal.
    fn cancel_proposal(e: Env) -> Result<(), UpgradeError>;
}
