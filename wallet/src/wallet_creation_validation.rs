#![allow(unused)]
use crate::{data::DataKey, state::aggregate_bls_keys};
use socketfi_access::access::{read_fee_manager, read_registry, read_social_router};
use socketfi_shared::{
    bls::{g1_group_gen_point, is_g1_infinity},
    constants::{DST, MAX_BLS_KEYS, MIN_BLS_KEYS},
};

use socketfi_webauthn::{
    key_types::{extract_bls_keys, BlsKeyWithPoP, PasskeySignature},
    validate_passkey_assertion_data,
    wallet_error::WalletError,
};

use soroban_sdk::{
    crypto::bls12_381::{G1Affine, G2Affine},
    vec,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Map, String, Symbol, Vec,
};

// Aggregates all BLS public keys into a single canonical aggregate key.
// BLS aggregation is order-independent, meaning the resulting aggregate
// public key remains identical regardless of the ordering of `bls_keys`.
//
// This aggregate key is used as part of wallet address derivation to ensure
// the deployed wallet address commits to the intended BLS signer set rather
// than the passkey alone.
fn validate_bls_agg(env: &Env, bls_keys: Vec<BytesN<96>>) -> Result<BytesN<96>, WalletError> {
    let agg = aggregate_bls_keys(env, bls_keys)?;
    let point = G1Affine::from_bytes(agg.clone());

    if is_g1_infinity(&agg) {
        return Err(WalletError::KeyAtInfinity);
    }

    if !point.is_in_subgroup() {
        return Err(WalletError::InvalidBlsKey);
    }
    Ok(agg)
}

/// Verify proof-of-possession for a submitted BLS public key.
///
/// Notes:
/// - Validates ownership of the corresponding BLS private key.
/// - Verifies a signature over the wallet creation challenge.
/// - Prevents accepting signer keys not controlled by the submitter.
pub fn verify_each_bls_key(
    e: &Env,
    challenge: BytesN<32>,
    bls_key_pop: BlsKeyWithPoP,
) -> Result<(), WalletError> {
    // Access BLS12-381 operations from the Soroban crypto interface.
    let bls = e.crypto().bls12_381();

    let dst: Bytes = Bytes::from_slice(&e, DST.as_bytes());

    // Load the negative G1 generator used in the pairing equation.
    let neg_g1 = G1Affine::from_bytes(g1_group_gen_point(e));

    // Hash the payload into a point in G2 using the configured DST.
    let msg_g2 = bls.hash_to_g2(&challenge.into(), &dst);

    // Prepare the two input vectors for pairing verification.
    let vp1 = vec![&e, G1Affine::from_bytes(bls_key_pop.key), neg_g1];
    let vp2 = vec![&e, msg_g2, G2Affine::from_bytes(bls_key_pop.sig)];

    // Signature is valid only if the pairing equation holds.
    if !bls.pairing_check(vp1, vp2) {
        return Err(WalletError::InvalidPoPSignature);
    }
    Ok(())
}

/// Validate the submitted BLS signer set.
///
/// Notes:
/// - Enforces minimum and maximum signer limits.
/// - Rejects duplicate keys.
/// - Ensures each key is not at infinity and belongs to the correct subgroup.
/// - Verifies the resulting aggregate key is valid.
pub fn validate_bls_key_set(env: &Env, keys: Vec<BytesN<96>>) -> Result<BytesN<96>, WalletError> {
    if keys.len() < MIN_BLS_KEYS {
        return Err(WalletError::InsufficientKeys);
    }

    if keys.len() > MAX_BLS_KEYS {
        return Err(WalletError::TooManyKeys);
    }

    let mut seen: Map<BytesN<96>, bool> = Map::new(env);

    for key in keys.iter() {
        if seen.contains_key(key.clone()) {
            return Err(WalletError::DuplicateKeys);
        }

        seen.set(key.clone(), true);
        let point = G1Affine::from_bytes(key.clone());

        if is_g1_infinity(&key) {
            return Err(WalletError::KeyAtInfinity);
        }

        if !point.is_in_subgroup() {
            return Err(WalletError::InvalidBlsKey);
        }
    }

    let agg = validate_bls_agg(env, keys)?;

    Ok(agg)
}

/// Validate and verify the wallet creation BLS signer set.
///
/// Notes:
/// - Extracts submitted BLS public keys.
/// - Validates signer count and key integrity.
/// - Verifies proof-of-possession for every signer.
/// - Computes and returns the aggregated BLS public key.
pub fn validate_verify_bls_key_set_pop(
    env: &Env,
    challenge: BytesN<32>,
    bls_keys_pop: Vec<BlsKeyWithPoP>,
) -> Result<BytesN<96>, WalletError> {
    let keys = extract_bls_keys(&env, bls_keys_pop.clone());
    let agg = validate_bls_key_set(env, keys)?;

    for bls_key_pop in bls_keys_pop.iter() {
        verify_each_bls_key(&env, challenge.clone(), bls_key_pop)?;
    }
    Ok(agg)
}

/// Verify passkey proof-of-possession for wallet creation.
///
/// Notes:
/// - Validates the WebAuthn assertion for the creation challenge.
/// - Verifies RP ID hash binding.
/// - Enforces user presence and verification requirements.
/// - Verifies the P-256 signature over the WebAuthn payload.
pub fn verify_passkey_pop(
    env: &Env,
    challenge: BytesN<32>,
    passkey: BytesN<65>,
    passkey_sig: PasskeySignature,
    expected_rpid_hash: BytesN<32>,
) -> Result<(), WalletError> {
    validate_passkey_assertion_data(
        env,
        challenge,
        expected_rpid_hash.into(),
        passkey_sig.clone().authenticator_data,
        passkey_sig.clone().client_data_json,
    )?;

    let client_data_hash = env.crypto().sha256(&passkey_sig.client_data_json);

    let mut signed_payload = passkey_sig.authenticator_data.clone();
    signed_payload.extend_from_array(&client_data_hash.to_array());

    let digest = env.crypto().sha256(&signed_payload);
    env.crypto()
        .secp256r1_verify(&passkey, &digest, &passkey_sig.signature);

    Ok(())
}
