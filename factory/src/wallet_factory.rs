#![allow(unused)]
use crate::data::DataKey;
use socketfi_shared::{
    bls::{g1_group_gen_point, is_g1_infinity},
    constants::{DST, MAX_BLS_KEYS, MIN_BLS_KEYS},
    key_types::{BlsKeyWithPoP, PasskeySignature},
    ttl::bump_instance,
    wallet_error::WalletError,
};

use soroban_sdk::{
    crypto::bls12_381::{G1Affine, G2Affine},
    vec,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Map, String, Symbol, Vec,
};
use upgrade::read_wallet_wasm_hash;

fn validate_network(e: &Env, network: &Symbol) -> Result<(), WalletError> {
    let testnet = Symbol::new(e, "TESTNET");
    let public = Symbol::new(e, "PUBLIC");

    if *network != testnet && *network != public {
        return Err(WalletError::InvalidNetwork);
    }

    Ok(())
}

pub fn read_rpid_hash(e: &Env) -> Result<BytesN<32>, WalletError> {
    bump_instance(e);
    e.storage()
        .instance()
        .get(&DataKey::RPIDHash)
        .ok_or(WalletError::RpidNotFound)
}
pub fn write_rpid_hash(e: &Env, rpid: &String) {
    let rpid_bytes = rpid.to_bytes();
    let rpid_hash: BytesN<32> = e.crypto().sha256(&rpid_bytes).into();
    bump_instance(e);
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
    passkey_sig: PasskeySignature,
    bls_keys_pop: Vec<BlsKeyWithPoP>,
    challenge: BytesN<32>,
    guardians: Vec<Address>,
) -> Result<Address, WalletError> {
    // Load the approved wallet wasm version for deployment.
    let wasm = read_wallet_wasm_hash(&e).unwrap();

    // Load the configured RP ID hash bound to passkey verification.
    let rpid_hash = read_rpid_hash(e)?;

    // Deploy using the verified creation challenge as the deterministic salt.
    // The challenge is only accepted after passkey PoP and BLS PoP verification.
    let wallet_address = e
        .deployer()
        .with_current_contract(challenge.clone())
        .deploy_v2(
            wasm,
            (
                challenge,
                passkey,
                passkey_sig,
                rpid_hash,
                bls_keys_pop,
                guardians,
            ),
        );

    Ok(wallet_address)
}
