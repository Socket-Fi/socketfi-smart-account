use soroban_sdk::{
    crypto::bls12_381::{G1Affine, G2Affine},
    vec, Bytes, BytesN, Env,
};

use crate::states::{read_agg_bls_key, read_passkey, read_rpid_hash};
use socketfi_shared::{
    bls::g1_group_gen_point, constants::DST, key_types::PasskeySignature,
    wallet_error::WalletError, webauthn_validation::validate_passkey_assertion_data,
};

/// Return the domain separation tag as contract bytes.
///
/// Notes:
/// - Converts the shared BLS DST constant into `Bytes` for hashing.
/// - Used during message hashing in signature verification.
fn read_dst_bytes(e: &Env) -> Bytes {
    Bytes::from_slice(&e, DST.as_bytes())
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
    let expected_rpid_hash = read_rpid_hash(env).ok_or(WalletError::RpidNotFound)?;

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
/// - Hashes the provided challenge into G2 using the configured DST.
/// - Verifies the signature using a pairing check.
/// - Returns `InvalidSignature` if verification fails.
/// - Updates the nonce only after a successful verification.
/// - Current implementation assumes the aggregated public key exists and
///   uses `unwrap()`, so missing key material would panic.
pub fn verify_bls_key(
    env: &Env,
    challenge: BytesN<32>,
    tx_signature: BytesN<192>,
) -> Result<(), WalletError> {
    // Access BLS12-381 operations from the Soroban crypto interface.
    let bls = env.crypto().bls12_381();

    // Read aggregated public key and domain separation tag used for verification.
    let agg_pk: BytesN<96> = read_agg_bls_key(&env).unwrap();
    let dst: Bytes = read_dst_bytes(&env);

    // Load the negative G1 generator used in the pairing equation.
    let neg_g1 = G1Affine::from_bytes(g1_group_gen_point(env));

    // Hash the challenge into a point in G2 using the configured DST.
    let msg_g2 = bls.hash_to_g2(&challenge.into(), &dst);

    // Prepare the two input vectors for pairing verification.
    let vp1 = vec![&env, G1Affine::from_bytes(agg_pk), neg_g1];
    let vp2 = vec![&env, msg_g2, G2Affine::from_bytes(tx_signature)];

    // Signature is valid only if the pairing equation holds.
    if !bls.pairing_check(vp1, vp2) {
        return Err(WalletError::InvalidSignature);
    }

    Ok(())
}

pub fn authorize_recovery(
    env: Env,
    challenge: BytesN<32>,
    agg_bls_sig: BytesN<192>,
) -> Result<(), WalletError> {
    verify_bls_key(&env, challenge, agg_bls_sig)?;
    Ok(())
}
