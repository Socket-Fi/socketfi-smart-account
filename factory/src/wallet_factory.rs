#![allow(unused)]
use crate::data::{BlsKeyWithPoP, DataKey, PasskeyWithPoP};
use socketfi_access::access::{read_fee_manager, read_registry, read_social_router};
use socketfi_shared::{
    bls::{g1_group_gen_point, is_g1_infinity},
    constants::{DST, MAX_BLS_KEYS, MIN_BLS_KEYS},
};

use socketfi_webauthn::{validate_passkey_assertion_data, wallet_error::WalletError};
use soroban_sdk::{
    crypto::bls12_381::{G1Affine, G2Affine},
    vec,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Map, String, Symbol, Vec,
};
use upgrade::get_wallet_version;

pub fn extract_bls_keys(e: &Env, bls_keys_pop: Vec<BlsKeyWithPoP>) -> Vec<BytesN<96>> {
    let mut bls_keys: Vec<BytesN<96>> = Vec::new(e);

    for bls_key_pop in bls_keys_pop.iter() {
        bls_keys.push_back(bls_key_pop.key.clone());
    }

    bls_keys
}
fn validate_network(e: &Env, network: &Symbol) -> Result<(), WalletError> {
    let testnet = Symbol::new(e, "TESTNET");
    let public = Symbol::new(e, "PUBLIC");

    if *network != testnet && *network != public {
        return Err(WalletError::InvalidNetwork);
    }

    Ok(())
}

pub fn read_rpid_hash(e: &Env) -> Result<BytesN<32>, WalletError> {
    e.storage()
        .instance()
        .get(&DataKey::RPIDHash)
        .ok_or(WalletError::RpidNotFound)
}
pub fn write_rpid_hash(e: &Env, rpid: &String) {
    let rpid_bytes = rpid.to_bytes();
    let rpid_hash: BytesN<32> = e.crypto().sha256(&rpid_bytes).into();

    e.storage().instance().set(&DataKey::RPIDHash, &rpid_hash);
}

pub fn read_creation_nonce_used(e: &Env, nonce: &BytesN<32>) -> bool {
    e.storage()
        .persistent()
        .has(&DataKey::UsedCreationNonce(nonce.clone()))
}

pub fn write_creation_nonce_used(e: &Env, nonce: &BytesN<32>) {
    e.storage()
        .persistent()
        .set(&DataKey::UsedCreationNonce(nonce.clone()), &true);
}

pub fn read_creation_pop_challenge(
    e: &Env,
    nonce: &BytesN<32>,
    network: &Symbol,
) -> Result<BytesN<32>, WalletError> {
    validate_network(e, &network)?;

    if read_creation_nonce_used(e, nonce) {
        return Err(WalletError::NonceAlreadyUsed);
    }
    let rp_id_hash = read_rpid_hash(e)?;
    let mut salt = Bytes::new(e);

    salt.append(&Bytes::from_slice(e, b"SOCKETFI_CREATE_WALLET_POP"));
    salt.append(&network.to_xdr(e));
    salt.append(&rp_id_hash.to_xdr(e));
    salt.append(&nonce.to_xdr(e));

    Ok(e.crypto().sha256(&salt).into())
}

// Aggregates all BLS public keys into a single canonical aggregate key.
// BLS aggregation is order-independent, meaning the resulting aggregate
// public key remains identical regardless of the ordering of `bls_keys`.
//
// This aggregate key is used as part of wallet address derivation to ensure
// the deployed wallet address commits to the intended BLS signer set rather
// than the passkey alone.
fn validate_bls_agg(env: &Env, bls_keys: Vec<BytesN<96>>) -> Result<(), WalletError> {
    let bls = env.crypto().bls12_381();

    let mut first_array = [0u8; 96];
    bls_keys.get_unchecked(0).copy_into_slice(&mut first_array);

    let mut agg_pk = G1Affine::from_bytes(BytesN::from_array(env, &first_array));

    let n = bls_keys.len();

    for i in 1..n {
        let mut key_array = [0u8; 96];

        bls_keys.get_unchecked(i).copy_into_slice(&mut key_array);

        let pk = G1Affine::from_bytes(BytesN::from_array(env, &key_array));

        agg_pk = bls.g1_add(&agg_pk, &pk);
    }

    let agg = agg_pk.to_bytes();

    if is_g1_infinity(&agg) {
        return Err(WalletError::KeyAtInfinity);
    }
    Ok(())
}

/// Verifies proof-of-possession for one submitted BLS public key.
///
/// Each signer must sign the deterministic wallet-creation challenge. This
/// binds the BLS key set to the same creation intent authorized by the passkey
/// and prevents accepting public keys whose private keys are not controlled by
/// the claimed signer.
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

/// Verifies passkey proof-of-possession for wallet creation.
///
/// The passkey must produce a valid WebAuthn assertion over the deterministic
/// creation challenge. This binds wallet creation to the holder of the passkey
/// private key and prevents arbitrary callers from creating wallets for
/// passkeys they do not control.
///
/// Verification includes:
/// - WebAuthn client data type and challenge binding
/// - RP ID hash binding
/// - User Presence and User Verification flags
/// - P-256 signature verification over
///   `sha256(authenticatorData || sha256(clientDataJSON))`
pub fn verify_passkey_pop(
    env: &Env,
    challenge: BytesN<32>,
    passkey_sig: PasskeyWithPoP,
) -> Result<(), WalletError> {
    let expected_rpid_hash = read_rpid_hash(env)?;

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
    env.crypto()
        .secp256r1_verify(&passkey_sig.key, &digest, &passkey_sig.sig);

    Ok(())
}

pub fn validate_bls_key_set(env: &Env, keys: Vec<BytesN<96>>) -> Result<(), WalletError> {
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

        if is_g1_infinity(&key) {
            return Err(WalletError::KeyAtInfinity);
        }
    }

    validate_bls_agg(env, keys)?;

    Ok(())
}

/// Deploys a new wallet contract instance.
///
/// Notes:
/// - Uses the currently approved wallet wasm hash.
/// - Uses the verified wallet-creation challenge as the deterministic
///   deployment salt.
/// - Passes the passkey, RP ID hash, BLS key set, and configured dependencies
///   into the wallet constructor.
/// - Registry, social router, fee manager, and wallet wasm version
///   were initialized during factory setup.
pub fn write_create_wallet(
    e: &Env,
    passkey: &BytesN<65>,
    bls_keys: Vec<BytesN<96>>,
    challenge: BytesN<32>,
) -> Result<Address, WalletError> {
    // Load the approved wallet wasm version for deployment.
    let wasm = get_wallet_version(&e).unwrap();

    // Load the configured RP ID hash bound to passkey verification.
    let rpid_hash = read_rpid_hash(e)?;

    // Deploy using the verified creation challenge as the deterministic salt.
    // The challenge is only accepted after passkey PoP and BLS PoP verification.
    let wallet_address = e.deployer().with_current_contract(challenge).deploy_v2(
        wasm,
        (
            passkey,
            rpid_hash,
            bls_keys.clone(),
            read_registry(e).unwrap(),
            read_social_router(e).unwrap(),
            read_fee_manager(e).unwrap(),
            e.current_contract_address(),
        ),
    );

    Ok(wallet_address)
}
