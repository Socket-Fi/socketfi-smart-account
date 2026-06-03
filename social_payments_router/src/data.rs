use soroban_sdk::{contracttype, Address, BytesN, String};
#[derive(Clone)]
#[contracttype]
pub enum PaymentResult {
    Direct(Address),
    Pending(BytesN<32>),
}

/// Represents a stored pending payment.
#[derive(Clone)]
#[contracttype]
pub struct PendingPayment {
    pub payment_id: BytesN<32>,
    pub sender: Address,
    pub asset: Address,
    pub amount: i128,
    pub platform: String,
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub status: PaymentStatus,
    pub claimed_by: Option<Address>,
}

/// Lifecycle state of a payment.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PaymentStatus {
    Pending,
    Claimed,
    Refunded,
}

/// Storage keys for contract state.
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    IdentityPayments(BytesN<32>),
    SenderPayments(Address),
    PaymentNonce,
    Payment(BytesN<32>),
}
