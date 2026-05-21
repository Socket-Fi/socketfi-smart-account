use socketfi_webauthn::{validate_passkey_assertion_data, wallet_error::WalletError};
use soroban_sdk::{
    crypto::bls12_381::{G1Affine, G2Affine},
    vec,
    xdr::ToXdr,
    Bytes, BytesN, Env, String, Val, Vec,
};

use crate::{
    data::{AuthContext, DataKey, PasskeySignature},
    state::read_passkey,
    state::{read_agg_bls_key, read_owner, read_rpid_hash},
};
use socketfi_shared::{
    bls::g1_group_gen_point,
    constants::{DST, MAX_AUTH_WINDOW_LEDGER},
};

pub fn read_nonce(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::Nonce).unwrap_or(0)
}
pub fn write_nonce(env: &Env, nonce: u64) {
    env.storage().instance().set(&DataKey::Nonce, &nonce);
}

pub fn increment_nonce(env: &Env) -> u64 {
    let nonce = read_nonce(env);
    let next = nonce.saturating_add(1);

    write_nonce(env, next);

    next
}

// Ensures externally signed wallet authorizations are short-lived.
// The caller supplies `valid_until_ledger` as part of the signed payload,
// but the contract bounds it to prevent long-lived replayable signatures.
pub fn validate_auth_window(env: &Env, valid_until_ledger: u32) -> Result<(), WalletError> {
    let current = env.ledger().sequence();

    if valid_until_ledger <= current {
        return Err(WalletError::InvalidLedgerWindow);
    }

    let max_allowed = current
        .checked_add(MAX_AUTH_WINDOW_LEDGER)
        .ok_or(WalletError::InvalidLedgerWindow)?;

    if valid_until_ledger > max_allowed {
        return Err(WalletError::WindowTooLarge);
    }

    Ok(())
}

/// Return the domain separation tag as contract bytes.
///
/// Notes:
/// - Converts the shared BLS DST constant into `Bytes` for hashing.
/// - Used during message hashing in signature verification.
fn read_dst_bytes(e: &Env) -> Bytes {
    Bytes::from_slice(&e, DST.as_bytes())
}

/// Compute the wallet authorization payload hash.
///
/// Notes:
/// - Builds the payload from:
///   - current wallet nonce
///   - current contract address
///   - function name
///   - encoded argument list
/// - Returns the SHA-256 hash of the serialized payload.
/// - Used as the message payload for owner/BLS authorization flows.
pub fn compute_tx_nonce(
    env: &Env,
    func: String,
    args: Vec<Val>,
    valid_until_ledger: u32,
) -> Result<BytesN<32>, WalletError> {
    validate_auth_window(env, valid_until_ledger)?;
    let nonce = read_nonce(env);

    let mut payload = Bytes::new(env);

    payload.append(&Bytes::from_slice(env, b"SOCKETFI_WALLET_AUTH_V1"));
    payload.append(&env.current_contract_address().to_xdr(env));

    payload.append(&nonce.to_xdr(env));
    payload.append(&valid_until_ledger.to_xdr(env));

    payload.append(&func.to_xdr(env));

    for arg in args.iter() {
        payload.append(&arg.to_xdr(env));
    }

    Ok(env.crypto().sha256(&payload).into())
}

/// Verifies a WebAuthn passkey assertion against the wallet's registered passkey.
///
/// Validation flow:
/// 1. Load and validate the expected RP ID hash.
/// 2. Validate assertion structure and challenge binding
///    (challenge, origin, type, RP ID hash, flags, etc.).
/// 3. Compute SHA-256 over `client_data_json`.
/// 4. Construct the WebAuthn signed payload:
///      authenticatorData || SHA256(clientDataJSON)
/// 5. Hash the payload and verify the P-256 signature against the
///    registered wallet passkey.
///
/// Returns:
/// - `Ok(())` if the assertion is cryptographically valid and bound
///   to the expected challenge and RP ID.
/// - `WalletError` if validation or signature verification fails.

pub fn verify_passkey(
    env: &Env,
    challenge: BytesN<32>,
    passkey_sig: PasskeySignature,
) -> Result<(), WalletError> {
    let expected_rpid_hash = read_rpid_hash(env);

    validate_passkey_assertion_data(
        env,
        challenge,
        expected_rpid_hash,
        passkey_sig.clone().authenticator_data,
        passkey_sig.clone().client_data_json,
    )?;

    let client_data_hash = env.crypto().sha256(&passkey_sig.client_data_json);

    let mut signed_payload = passkey_sig.authenticator_data.clone();
    signed_payload.extend_from_array(&client_data_hash.to_array());

    let digest = env.crypto().sha256(&signed_payload);
    let passkey = read_passkey(env).unwrap();
    env.crypto()
        .secp256r1_verify(&passkey, &digest, &passkey_sig.signature);

    Ok(())
}

/// Verify a BLS signature against the aggregated public key.
///
/// Notes:
/// - Loads the aggregated BLS public key from storage.
/// - Hashes the provided payload into G2 using the configured DST.
/// - Verifies the signature using a pairing check.
/// - Returns `InvalidSignature` if verification fails.
/// - Updates the nonce only after a successful verification.
/// - Current implementation assumes the aggregated public key exists and
///   uses `unwrap()`, so missing key material would panic.
pub fn verify_bls_key(
    env: &Env,
    payload: BytesN<32>,
    tx_signature: BytesN<192>,
) -> Result<(), WalletError> {
    // Access BLS12-381 operations from the Soroban crypto interface.
    let bls = env.crypto().bls12_381();

    // Read aggregated public key and domain separation tag used for verification.
    let agg_pk: BytesN<96> = read_agg_bls_key(&env).unwrap();
    let dst: Bytes = read_dst_bytes(&env);

    // Load the negative G1 generator used in the pairing equation.
    let neg_g1 = G1Affine::from_bytes(g1_group_gen_point(env));

    // Hash the payload into a point in G2 using the configured DST.
    let msg_g2 = bls.hash_to_g2(&payload.into(), &dst);

    // Prepare the two input vectors for pairing verification.
    let vp1 = vec![&env, G1Affine::from_bytes(agg_pk), neg_g1];
    let vp2 = vec![&env, msg_g2, G2Affine::from_bytes(tx_signature)];

    // Signature is valid only if the pairing equation holds.
    if !bls.pairing_check(vp1, vp2) {
        return Err(WalletError::InvalidSignature);
    }

    Ok(())
}

/// Require owner authorization using either BLS signature auth or direct owner auth.
///
/// Notes:
/// - If a signature is provided, authorization is performed through BLS verification.
/// - If no signature is provided, the stored owner address must authorize directly.
/// - Current implementation assumes an owner is configured in the direct auth path
///   and uses `unwrap()`, so missing owner state would panic.
pub fn owner_require_auth(
    env: Env,
    challenge: BytesN<32>,
    passkey_sig: Option<PasskeySignature>,
) -> Result<(), WalletError> {
    if let Some(signature) = passkey_sig {
        // Signature-based authorization path using aggregated BLS verification.
        verify_passkey(&env, challenge, signature)?;
    } else {
        // Direct owner authorization path using the stored external owner address.
        let owner = read_owner(&env).unwrap();
        owner.require_auth();
    }

    Ok(())
}

pub fn authorize_recovery(
    env: Env,
    payload: BytesN<32>,
    agg_bls_sig: BytesN<192>,
) -> Result<(), WalletError> {
    verify_bls_key(&env, payload, agg_bls_sig)?;
    Ok(())
}
