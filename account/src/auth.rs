use soroban_sdk::{
    crypto::{
        bls12_381::{G1Affine, G2Affine},
        Hash,
    },
    vec, Bytes, BytesN, Env,
};

use crate::states::{
    read_agg_bls_key, read_evm_signer, read_passkey, read_rpid_hash, read_stellar_signer,
};
use socketfi_shared::{
    account_error::AccountError,
    bls::g1_group_gen_point,
    constants::{DST, ETH_PERSONAL_SIGN_PREFIX_32},
    key_types::{BlsSignature, EvmSignature, PasskeySignature, StellarSignature},
    webauthn_validation::validate_passkey_assertion_data,
};

/// Return the domain separation tag as contract bytes.
///
/// Notes:
/// - Converts the shared BLS DST constant into `Bytes` for hashing.
/// - Used during message hashing in signature verification.
fn read_dst_bytes(e: &Env) -> Bytes {
    Bytes::from_slice(&e, DST.as_bytes())
}

/// Verifies a WebAuthn passkey assertion against the account's registered passkey.
///
/// Validation flow:
/// 1. Load and validate the expected RP ID hash.
/// 2. Validate assertion structure and challenge binding
///    (challenge, origin, type, RP ID hash, flags, etc.).
/// 3. Compute SHA-256 over `client_data_json`.
/// 4. Construct the WebAuthn signed payload:
///      authenticatorData || SHA256(clientDataJSON)
/// 5. Hash the payload and verify the P-256 signature against the
///    registered account passkey.
///
/// Returns:
/// - `Ok(())` if the assertion is cryptographically valid and bound
///   to the expected challenge and RP ID.
/// - `AccountError` if validation or signature verification fails.

pub fn verify_passkey(
    env: &Env,
    challenge: BytesN<32>,
    passkey_sig: PasskeySignature,
) -> Result<(), AccountError> {
    let expected_rpid_hash = read_rpid_hash(env).ok_or(AccountError::RpidNotFound)?;

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

pub fn verify_stellar(
    env: &Env,
    signature_payload: &Hash<32>,
    signature: StellarSignature,
) -> Result<(), AccountError> {
    let public_key = read_stellar_signer(env).ok_or(AccountError::StellarSignerNotFound)?;

    env.crypto().ed25519_verify(
        &public_key,
        &signature_payload.clone().into(),
        &signature.signature,
    );

    Ok(())
}

pub fn verify_evm(
    env: &Env,
    signature_payload: &Hash<32>,
    evm_signature: EvmSignature,
) -> Result<(), AccountError> {
    // Ethereum recovery identifiers accepted by Soroban are 0 or 1.
    if evm_signature.recovery_id > 1 {
        return Err(AccountError::InvalidEvmRecoveryId);
    }

    let expected_address = read_evm_signer(env).ok_or(AccountError::EvmSignerNotFound)?;

    /*
     * MetaMask personal_sign does not sign the supplied bytes directly.
     * It signs:
     *
     * keccak256(
     *   "\x19Ethereum Signed Message:\n32" ||
     *   soroban_signature_payload
     * )
     */
    let mut ethereum_message = Bytes::from_slice(env, ETH_PERSONAL_SIGN_PREFIX_32);

    let soroban_payload: BytesN<32> = signature_payload.clone().into();

    let payload_bytes: Bytes = soroban_payload.into();
    ethereum_message.append(&payload_bytes);

    let ethereum_digest = env.crypto().keccak256(&ethereum_message);

    /*
     * Returned key is a 65-byte uncompressed SEC-1 key:
     *
     * 0x04 || X[32] || Y[32]
     */
    let recovered_public_key = env.crypto().secp256k1_recover(
        &ethereum_digest,
        &evm_signature.signature,
        evm_signature.recovery_id,
    );

    if recovered_public_key.get(0) != Some(0x04) {
        return Err(AccountError::InvalidSignature);
    }

    /*
     * Ethereum address:
     *
     * last_20_bytes(
     *   keccak256(uncompressed_public_key[1..65])
     * )
     */
    let mut raw_public_key = Bytes::new(env);

    for index in 1u32..65u32 {
        raw_public_key.push_back(
            recovered_public_key
                .get(index)
                .ok_or(AccountError::InvalidSignature)?,
        );
    }

    let public_key_hash: BytesN<32> = env.crypto().keccak256(&raw_public_key).into();

    for index in 0u32..20 {
        let recovered_byte = public_key_hash
            .get(index + 12)
            .ok_or(AccountError::InvalidSignature)?;

        let expected_byte = expected_address
            .get(index)
            .ok_or(AccountError::InvalidSignature)?;

        if recovered_byte != expected_byte {
            return Err(AccountError::InvalidSignature);
        }
    }

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
) -> Result<(), AccountError> {
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
        return Err(AccountError::InvalidSignature);
    }

    Ok(())
}

pub fn verify_bls_recovery_signature(
    env: &Env,
    challenge: BytesN<32>,
    recovery_signature: BlsSignature,
) -> Result<(), AccountError> {
    verify_bls_key(env, challenge, recovery_signature.signature)?;
    Ok(())
}
