use socketfi_webauthn::{__validate_passkey_assertion_data, wallet_error::WalletError};
use soroban_sdk::{
    crypto::bls12_381::{G1Affine, G2Affine},
    vec,
    xdr::ToXdr,
    Bytes, BytesN, Env, String, Val, Vec,
};

use crate::{
    data::{DataKey, PasskeySignature},
    state::read_passkey,
    state::{read_agg_bls_key, read_owner, read_rpid_hash},
};
use socketfi_shared::{bls::g1_group_gen_point, constants::DST};

/// Return the domain separation tag as contract bytes.
///
/// Notes:
/// - Converts the shared BLS DST constant into `Bytes` for hashing.
/// - Used during message hashing in signature verification.
fn read_dst_bytes(e: &Env) -> Bytes {
    Bytes::from_slice(&e, DST.as_bytes())
}

/// Read the current replay-protection nonce from instance storage.
///
/// Notes:
/// - Returns the stored nonce when present.
/// - Returns `0` if nonce has not yet been initialized.
pub fn read_nonce(env: &Env) -> u64 {
    env.storage().instance().get(&DataKey::Nonce).unwrap_or(0)
}

/// Write the replay-protection nonce to instance storage.
///
/// Notes:
/// - Replaces any previously stored nonce value.
pub fn write_nonce(env: &Env, nonce: u64) {
    env.storage().instance().set(&DataKey::Nonce, &nonce);
}

/// Increment the replay-protection nonce by one.
///
/// Notes:
/// - Reads the current nonce, increments it, and stores the new value.
/// - Panics if `checked_add(1)` overflows.
pub fn update_nonce(env: &Env) {
    let nonce = read_nonce(env);
    let n = nonce.checked_add(1).expect("invalid nonce");
    env.storage().instance().set(&DataKey::Nonce, &n);
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
pub fn compute_tx_nonce(env: &Env, func: String, args: Vec<Val>) -> BytesN<32> {
    let wallet_nonce = read_nonce(env);
    let mut payload = wallet_nonce.to_xdr(env);

    payload.append(&env.current_contract_address().to_xdr(env));
    payload.append(&func.to_xdr(env));

    for b in args.iter() {
        let x = b.to_xdr(env);
        payload.append(&x);
    }

    BytesN::from(env.crypto().sha256(&payload))
}

pub fn __verify_passkey(
    env: &Env,
    challenge: BytesN<32>,
    passkey_sig: PasskeySignature,
) -> Result<(), WalletError> {
    let expected_rpid_hash = read_rpid_hash(env);

    __validate_passkey_assertion_data(
        env,
        challenge,
        expected_rpid_hash,
        passkey_sig.clone().authenticator_data,
        passkey_sig.clone().client_data_json,
    )?;

    let client_data_hash: BytesN<32> = env.crypto().sha256(&passkey_sig.client_data_json).into();

    let mut signed_payload = Bytes::new(&env);

    // authenticatorData
    signed_payload.append(&passkey_sig.authenticator_data);

    // sha256(clientDataJSON)
    let mut i = 0;
    while i < 32 {
        signed_payload.push_back(client_data_hash.get_unchecked(i));
        i += 1;
    }
    let digest = env.crypto().sha256(&signed_payload);
    let passkey = read_passkey(env).unwrap();
    env.crypto()
        .secp256r1_verify(&passkey, &digest, &passkey_sig.signature);

    update_nonce(env);
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
pub fn __verify_bls_key(
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

    // Advance the nonce only after successful signature verification.
    update_nonce(env);
    Ok(())
}

/// Require owner authorization using either BLS signature auth or direct owner auth.
///
/// Notes:
/// - If a signature is provided, authorization is performed through BLS verification.
/// - If no signature is provided, the stored owner address must authorize directly.
/// - Current implementation assumes an owner is configured in the direct auth path
///   and uses `unwrap()`, so missing owner state would panic.
pub fn __owner_require_auth(
    env: Env,
    challenge: BytesN<32>,
    passkey_sig: Option<PasskeySignature>,
) -> Result<(), WalletError> {
    if let Some(signature) = passkey_sig {
        // Signature-based authorization path using aggregated BLS verification.
        __verify_passkey(&env, challenge, signature)?;
        // fee_manager_deep_auth()
    } else {
        // Direct owner authorization path using the stored external owner address.
        let owner = read_owner(&env).unwrap();
        owner.require_auth();
    }

    Ok(())
}

pub fn __authorize_recovery(
    env: Env,
    payload: BytesN<32>,
    agg_bls_sig: BytesN<192>,
) -> Result<(), WalletError> {
    __verify_bls_key(&env, payload, agg_bls_sig)?;
    Ok(())
}
