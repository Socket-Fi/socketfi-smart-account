use soroban_sdk::{
    contract, contractimpl, vec, Address, BytesN, Env, IntoVal, String, Symbol, Val, Vec,
};

use crate::{
    contract_trait::SocialPaymentsTrait,
    data::{PaymentResult, PaymentStatus, PendingPayment},
    nonce::{read_payment_nonce, write_payment_nonce},
    payment::{
        append_identity_payment, append_sender_payment, claim_one, generate_payment_id, now,
        read_identity_payment_ids, read_payment, read_sender_payment_ids, refund_one,
        write_payment,
    },
};
use socketfi_access::access::{
    authenticate_admin, has_admin, read_registry, write_admin, write_registry,
};
use socketfi_shared::{
    constants::DEFAULT_CLAIM_PERIOD_SECONDS,
    events,
    registry_errors::RegistryError,
    tokens::{
        read_is_supported_asset, read_supported_assets, send_asset, take_asset, write_add_asset,
        write_remove_asset,
    },
    utils::validate_userid,
};
use upgrade::{
    cancel_upgrade_proposal, create_upgrade_proposal, errors::UpgradeError, execute_upgrade,
    upgrade_add_voter, write_cast_vote,
};

/// Social payments router contract.
///
/// Notes:
/// - Routes payments to social identities.
/// - Sends directly when identity resolves to a wallet.
/// - Otherwise stores a pending payment for later claim.
/// - Includes admin config and upgrade governance.
#[contract]
pub struct SocialPayments;

#[contractimpl]
impl SocialPaymentsTrait for SocialPayments {
    // initialization

    /// Initialize router state.
    ///
    /// Notes:
    /// - Sets admin and registry.
    /// - Initializes payment nonce.
    /// - Intended to run once.
    fn __constructor(e: Env, admin: Address, registry: Address) -> Result<(), UpgradeError> {
        if has_admin(&e) {
            return Err(UpgradeError::AlreadyInitialized);
        }

        write_admin(&e, &admin);
        write_registry(&e, &registry);
        write_payment_nonce(&e, 0);

        Ok(())
    }

    // payments

    /// Pay to a social identity.
    ///
    /// Notes:
    /// - Requires sender auth.
    /// - Asset must be supported.
    /// - Sends directly if registry resolves a wallet.
    /// - Otherwise stores a pending payment and indexes it by identity and sender.
    fn pay_to_social(
        e: Env,
        from: Address,
        platform: String,
        user_id: String,
        asset: Address,
        amount: i128,
        duration: Option<u64>,
    ) -> Result<PaymentResult, RegistryError> {
        if !read_is_supported_asset(&e, asset.clone()) {
            return Err(RegistryError::UnsupportedAsset);
        }

        from.require_auth();

        if amount <= 0 {
            return Err(RegistryError::InvalidAmount);
        }

        validate_userid(user_id.clone())?;

        let claim_periond: u64 = duration.unwrap_or(DEFAULT_CLAIM_PERIOD_SECONDS);

        let args: Vec<Val> = vec![&e, platform.into_val(&e), user_id.into_val(&e)];

        if let Some(to) = e.invoke_contract(
            &read_registry(&e).unwrap(),
            &Symbol::new(&e, "get_wallet_by_userid"),
            args,
        ) {
            take_asset(&e, &from, &asset, amount);
            send_asset(&e, &to, &asset, amount);

            return Ok(PaymentResult::Direct(to));
        } else {
            take_asset(&e, &from, &asset, amount);

            let nonce = read_payment_nonce(&e);

            let payment_id = generate_payment_id(
                &e,
                from.clone(),
                asset.clone(),
                amount,
                platform.clone(),
                user_id.clone(),
                nonce,
            );

            let created_at = now(&e);
            let expires_at = created_at
                .checked_add(claim_periond)
                .expect("expects a valid expiration");

            let payment = PendingPayment {
                payment_id: payment_id.clone(),
                sender: from.clone(),
                asset,
                amount,
                platform: platform.clone(),
                user_id: user_id.clone(),
                created_at,
                expires_at,
                status: PaymentStatus::Pending,
                claimed_by: None,
            };

            write_payment(&e, &payment_id.clone(), &payment);
            append_identity_payment(&e, platform, user_id, payment_id.clone())?;
            let n = nonce.checked_add(1).expect("invalid value");
            write_payment_nonce(&e, n);
            append_sender_payment(&e, from, payment_id.clone());

            Ok(PaymentResult::Pending(payment_id))
        }
    }

    /// Claim a single pending payment.
    ///
    /// Notes:
    /// - Requires claimer auth.
    /// - Claim validation is delegated to `claim_one`.
    fn claim_payment(
        e: Env,
        claimer: Address,
        payment_id: BytesN<32>,
    ) -> Result<(), RegistryError> {
        claimer.require_auth();
        claim_one(&e, &claimer, &payment_id)
    }

    /// Claim multiple pending payments.
    ///
    /// Notes:
    /// - Requires claimer auth.
    /// - Processes claims sequentially.
    /// - Entire call fails if any claim fails.
    fn claim_payments(
        e: Env,
        claimer: Address,
        payment_ids: Vec<BytesN<32>>,
    ) -> Result<(), RegistryError> {
        claimer.require_auth();

        for payment_id in payment_ids.iter() {
            claim_one(&e, &claimer, &payment_id)?;
        }

        Ok(())
    }

    /// Refund a single payment.
    ///
    /// Notes:
    /// - Requires sender auth.
    /// - Refund eligibility is delegated to `refund_one`.
    fn refund_payment(
        e: Env,
        sender: Address,
        payment_id: BytesN<32>,
    ) -> Result<(), RegistryError> {
        sender.require_auth();
        refund_one(&e, &sender, &payment_id)
    }

    /// Refund multiple payments.
    ///
    /// Notes:
    /// - Requires sender auth.
    /// - Processes refunds sequentially.
    /// - Entire call fails if any refund fails.
    fn refund_payments(
        e: Env,
        sender: Address,
        payment_ids: Vec<BytesN<32>>,
    ) -> Result<(), RegistryError> {
        sender.require_auth();

        for payment_id in payment_ids.iter() {
            refund_one(&e, &sender, &payment_id)?;
        }

        Ok(())
    }

    // queries

    /// Get a stored payment by id.
    fn get_payment(e: Env, payment_id: BytesN<32>) -> Option<PendingPayment> {
        read_payment(&e, &payment_id)
    }

    /// Get current payment nonce.
    ///
    /// Notes:
    /// - Used for payment id generation.
    /// - Also tracks created payment sequence.
    fn get_nonce(e: Env) -> u64 {
        read_payment_nonce(&e)
    }

    /// Get payment ids for `(platform, user_id)`.
    fn get_identity_payments(
        e: Env,
        platform: String,
        user_id: String,
    ) -> Result<Vec<BytesN<32>>, RegistryError> {
        read_identity_payment_ids(&e, platform, user_id)
    }

    /// Get payment ids created by sender.
    fn get_sender_payments(e: Env, sender: Address) -> Vec<BytesN<32>> {
        read_sender_payment_ids(&e, sender)
    }

    /// Get total currently claimable amount for identity and asset.
    ///
    /// Notes:
    /// - Includes only pending, unexpired payments matching the asset.
    /// - Excludes expired and already processed payments.
    fn get_claimable_total(
        e: Env,
        platform: String,
        user_id: String,
        asset: Address,
    ) -> Result<i128, RegistryError> {
        let ids = read_identity_payment_ids(&e, platform, user_id)?;
        let current_time = now(&e);
        let mut total: i128 = 0;

        for payment_id in ids.iter() {
            let payment = read_payment(&e, &payment_id).unwrap();

            if matches!(payment.status, PaymentStatus::Pending)
                && current_time < payment.expires_at
                && payment.asset == asset
            {
                total = total.checked_add(payment.amount).expect("invalid value");
            }
        }

        Ok(total)
    }

    /// Get all supported assets.
    fn get_supported_assets(e: Env) -> Vec<Address> {
        read_supported_assets(&e)
    }

    // admin/config

    /// Add supported asset.
    ///
    /// Notes:
    /// - Admin only.
    /// - Enables new payments in the asset.
    fn add_supported_asset(e: Env, asset: Address) {
        authenticate_admin(&e);
        write_add_asset(&e, asset);
    }

    /// Remove supported asset.
    ///
    /// Notes:
    /// - Admin only.
    /// - Blocks new payments in the asset.
    fn remove_supported_asset(e: Env, asset: Address) {
        authenticate_admin(&e);
        write_remove_asset(&e, asset);
    }

    /// Update admin.
    ///
    /// Notes:
    /// - Admin only.
    /// - Changes control over privileged router actions.
    fn set_admin(e: Env, new_admin: Address) {
        authenticate_admin(&e);
        write_admin(&e, &new_admin);
    }

    // upgrade governance

    /// Execute approved upgrade proposal.
    ///
    /// Notes:
    /// - Admin only.
    /// - Applies the current passed proposal.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError> {
        authenticate_admin(&e);
        execute_upgrade(&e)
    }

    /// Create upgrade proposal.
    ///
    /// Notes:
    /// - Admin only.
    /// - Starts governance flow for a new wasm hash.
    fn propose_upgrade(
        e: Env,
        proposal_type: String,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        create_upgrade_proposal(&e, proposal_type, &new_wasm_hash)?;
        Ok(())
    }

    /// Add governance voter.
    ///
    /// Notes:
    /// - Admin only.
    fn add_voter(e: Env, voter: Address) {
        authenticate_admin(&e);
        upgrade_add_voter(&e, &voter);

        events::AddVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);
    }

    /// Cast vote on active proposal.
    ///
    /// Notes:
    /// - Voter must authorize.
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
        cancel_upgrade_proposal(&e)?;
        Ok(())
    }

    /// Upgrade contract wasm directly.
    ///
    /// Notes:
    /// - Admin only.
    fn upgrade(e: Env, new_wasm_hash: BytesN<32>) {
        authenticate_admin(&e);
        e.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}
