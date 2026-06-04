use socketfi_shared::ttl::bump_instance;
use soroban_sdk::Env;

use crate::data::DataKey;

/// Read current payment nonce.
///
/// Returns:
/// - stored nonce
/// - `0` if not initialized
///
/// Notes:
/// - Used for payment id generation and sequencing.
///
/// Audit:
/// - Returning `0` as default is safe only if constructor initializes nonce
///   or first write happens before use.
pub fn read_payment_nonce(e: &Env) -> u64 {
    bump_instance(e);
    e.storage()
        .instance()
        .get(&DataKey::PaymentNonce)
        .unwrap_or(0)
}

/// Write updated payment nonce.
///
/// Notes:
/// - Overwrites existing nonce value.
pub fn write_payment_nonce(e: &Env, nonce: u64) {
    bump_instance(e);
    e.storage().instance().set(&DataKey::PaymentNonce, &nonce);
}
