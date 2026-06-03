use socketfi_access::access::read_registry;
use socketfi_shared::{
    registry_errors::RegistryError, tokens::send_asset, ttl::bump_persistent,
    utils::userid_payment_key,
};
use soroban_sdk::{xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal, String, Symbol, Val, Vec};

use crate::data::{DataKey, PaymentStatus, PendingPayment};

/// Get current ledger timestamp.
///
/// Notes:
/// - Used for payment expiry checks.
pub fn now(e: &Env) -> u64 {
    e.ledger().timestamp()
}

/// Deterministic payment id generator.
///
/// Notes:
/// - Combines sender, asset, identity, and nonce into hash.
/// - Ensures stable id for identical inputs.
///
/// Audit:
/// - Uniqueness depends on nonce monotonicity.
/// - Any reuse of nonce may cause id collision.
pub fn generate_payment_id(
    e: &Env,
    sender: Address,
    asset: Address,
    amount: i128,
    platform: String,
    user_id: String,
    nonce: u64,
) -> BytesN<32> {
    let mut data = Bytes::new(e);
    data.append(&String::from_str(e, "social_payment").to_xdr(e));
    data.append(&sender.to_xdr(e));
    data.append(&asset.to_xdr(e));
    data.append(&amount.to_xdr(e));
    data.append(&platform.to_xdr(e));
    data.append(&user_id.to_xdr(e));
    data.append(&nonce.to_xdr(e));

    e.crypto().sha256(&data).into()
}

/// Store payment state.
///
/// Notes:
/// - Overwrites existing entry if present.
///
/// Audit:
/// - Caller must ensure correct state transitions (no overwrite of finalized states).
pub fn write_payment(e: &Env, payment_id: &BytesN<32>, payment: &PendingPayment) {
    e.storage()
        .persistent()
        .set(&DataKey::Payment(payment_id.clone()), &payment);
}

/// Read payment by id.
///
/// Returns:
/// - `Some(PendingPayment)` if exists
/// - `None` if missing
pub fn read_payment(e: &Env, payment_id: &BytesN<32>) -> Option<PendingPayment> {
    e.storage()
        .persistent()
        .get(&DataKey::Payment(payment_id.clone()))
}

/// Append payment id to identity index.
///
/// Notes:
/// - Maintains `(platform, user_id) -> [payment_ids]` index.
///
/// Audit:
/// - Unbounded vector growth possible.
/// - No deduplication; assumes ids are unique.
pub fn append_identity_payment(
    e: &Env,
    platform: String,
    user_id: String,
    payment_id: BytesN<32>,
) -> Result<(), RegistryError> {
    let id_key = userid_payment_key(e, platform, user_id)?;
    let storage_key = DataKey::IdentityPayments(id_key);

    bump_persistent(e, &storage_key);
    let mut ids = e
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&storage_key)
        .unwrap_or_else(|| Vec::new(e));

    ids.push_back(payment_id);
    e.storage().persistent().set(&storage_key, &ids);

    Ok(())
}

/// Append payment id to sender index.
///
/// Notes:
/// - Maintains `sender -> [payment_ids]` index.
///
/// Audit:
/// - Unbounded growth possible.
/// - No pruning of old or completed payments.
pub fn append_sender_payment(e: &Env, from: Address, payment_id: BytesN<32>) {
    let storage_key = DataKey::SenderPayments(from);
    bump_persistent(e, &storage_key);
    let mut ids = e
        .storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&storage_key)
        .unwrap_or_else(|| Vec::new(e));

    ids.push_back(payment_id);
    e.storage().persistent().set(&storage_key, &ids);
}

/// Claim a pending payment.
///
/// Notes:
/// - Requires payment to be pending and not expired.
/// - Resolves identity via registry before claim.
/// - Transfers funds to claimer on success.
///
/// Audit:
/// - Relies on external registry for identity resolution.
/// - Uses `unwrap()` on storage read → assumes payment exists.
/// - State is updated before transfer to prevent reentrancy issues.
pub fn claim_one(e: &Env, claimer: &Address, payment_id: &BytesN<32>) -> Result<(), RegistryError> {
    let mut payment = read_payment(e, payment_id).unwrap();

    if !matches!(payment.status, PaymentStatus::Pending) {
        return Err(RegistryError::NotClaimable);
    }

    if now(e) >= payment.expires_at {
        return Err(RegistryError::Expired);
    }

    let args: Vec<Val> = Vec::from_array(
        e,
        [
            payment.platform.clone().into_val(e),
            payment.user_id.clone().into_val(e),
        ],
    );

    let resolved: Option<Address> = e.invoke_contract(
        &read_registry(e).unwrap(),
        &Symbol::new(e, "get_wallet_by_userid"),
        args,
    );

    if resolved != Some(claimer.clone()) {
        return Err(RegistryError::Unauthorized);
    }

    payment.status = PaymentStatus::Claimed;
    payment.claimed_by = Some(claimer.clone());
    write_payment(e, payment_id, &payment);

    send_asset(e, claimer, &payment.asset, payment.amount);
    Ok(())
}

/// Refund an expired pending payment.
///
/// Notes:
/// - Requires sender auth.
/// - Only valid after expiry.
/// - Transfers funds back to sender.
///
/// Audit:
/// - Uses `unwrap()` → assumes payment exists.
/// - Expiry check enforces claim/refund exclusivity.
/// - State updated before transfer.
pub fn refund_one(e: &Env, sender: &Address, payment_id: &BytesN<32>) -> Result<(), RegistryError> {
    let mut payment = read_payment(e, payment_id).unwrap();

    if !matches!(payment.status, PaymentStatus::Pending) {
        return Err(RegistryError::NotRefundable);
    }

    if payment.sender != *sender {
        return Err(RegistryError::Unauthorized);
    }

    if now(e) < payment.expires_at {
        return Err(RegistryError::NotExpired);
    }

    payment.status = PaymentStatus::Refunded;
    write_payment(e, payment_id, &payment);

    send_asset(e, sender, &payment.asset, payment.amount);

    Ok(())
}

/// Read payment ids for identity.
///
/// Notes:
/// - Returns empty vector if none found.
///
/// Audit:
/// - No filtering of expired or processed payments.
pub fn read_identity_payment_ids(
    e: &Env,
    platform: String,
    user_id: String,
) -> Result<Vec<BytesN<32>>, RegistryError> {
    let id_key = userid_payment_key(e, platform, user_id)?;
    let storage_key = DataKey::IdentityPayments(id_key);

    Ok(e.storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&storage_key)
        .unwrap_or_else(|| Vec::new(e)))
}

/// Read payment ids for sender.
///
/// Notes:
/// - Returns empty vector if none found.
pub fn read_sender_payment_ids(e: &Env, sender: Address) -> Vec<BytesN<32>> {
    let storage_key = DataKey::SenderPayments(sender);

    e.storage()
        .persistent()
        .get::<_, Vec<BytesN<32>>>(&storage_key)
        .unwrap_or_else(|| Vec::new(e))
}
