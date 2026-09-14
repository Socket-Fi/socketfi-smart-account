#![allow(unused)]
use crate::data::DataKey;
use socketfi_shared::{
    account_error::AccountError,
    bls::{g1_group_gen_point, is_g1_infinity},
    constants::{CREATION_DOMAIN, DST, MAX_BLS_KEYS, MAX_CREATION_WINDOW_LEDGERS, MIN_BLS_KEYS},
    key_types::{BlsKeyWithPoP, EvmSignature, PasskeySignature},
    ttl::bump_instance,
};

use soroban_sdk::{
    crypto::bls12_381::{G1Affine, G2Affine},
    vec,
    xdr::ToXdr,
    Address, Bytes, BytesN, Env, Map, String, Symbol, Vec,
};
use upgrade::read_account_wasm_hash;

fn validate_network(e: &Env, network: &Symbol) -> Result<(), AccountError> {
    let testnet = Symbol::new(e, "TESTNET");
    let public = Symbol::new(e, "PUBLIC");

    if *network != testnet && *network != public {
        return Err(AccountError::InvalidNetwork);
    }

    Ok(())
}

pub fn read_rpid_hash(e: &Env) -> Result<BytesN<32>, AccountError> {
    bump_instance(e);
    e.storage()
        .instance()
        .get(&DataKey::RPIDHash)
        .ok_or(AccountError::RpidNotFound)
}
pub fn write_rpid_hash(e: &Env, rpid: &String) {
    let rpid_bytes = rpid.to_bytes();
    let rpid_hash: BytesN<32> = e.crypto().sha256(&rpid_bytes).into();
    bump_instance(e);
    e.storage().instance().set(&DataKey::RPIDHash, &rpid_hash);
}

/// Keep honoring legacy persistent tombstones if this factory is upgraded.
pub fn read_creation_nonce_used(e: &Env, nonce: &BytesN<32>) -> bool {
    let key = DataKey::UsedCreationNonce(nonce.clone());
    e.storage().persistent().has(&key) || e.storage().temporary().has(&key)
}

pub fn validate_creation_expiry(e: &Env, live_until_ledger: u32) -> Result<(), AccountError> {
    let current = e.ledger().sequence();
    if live_until_ledger < current {
        return Err(AccountError::CreationProofExpired);
    }
    let duration = live_until_ledger - current;
    if duration > MAX_CREATION_WINDOW_LEDGERS || duration > e.storage().max_ttl() {
        return Err(AccountError::InvalidCreationExpiry);
    }
    Ok(())
}

pub fn write_creation_nonce_used(
    e: &Env,
    nonce: &BytesN<32>,
    live_until_ledger: u32,
) -> Result<(), AccountError> {
    validate_creation_expiry(e, live_until_ledger)?;
    let key = DataKey::UsedCreationNonce(nonce.clone());
    e.storage().temporary().set(&key, &true);
    // TTL is live-until minus current ledger. The proof is valid through the
    // expiry ledger, so the tombstone must remain readable through that ledger.
    let duration = live_until_ledger - e.ledger().sequence();
    e.storage().temporary().extend_ttl(&key, duration, duration);
    Ok(())
}

pub fn read_creation_pop_challenge(
    e: &Env,
    nonce: &BytesN<32>,
    network: &Symbol,
    live_until_ledger: u32,
) -> Result<BytesN<32>, AccountError> {
    validate_network(e, network)?;
    validate_creation_expiry(e, live_until_ledger)?;
    if read_creation_nonce_used(e, nonce) {
        return Err(AccountError::NonceAlreadyUsed);
    }
    let rp_id_hash = read_rpid_hash(e)?;
    let mut salt = Bytes::from_slice(e, CREATION_DOMAIN);
    salt.append(&e.ledger().network_id().to_xdr(e));
    salt.append(&e.current_contract_address().to_xdr(e));
    salt.append(&network.to_xdr(e));
    salt.append(&rp_id_hash.to_xdr(e));
    salt.append(&nonce.to_xdr(e));
    salt.append(&live_until_ledger.to_xdr(e));
    Ok(e.crypto().sha256(&salt).into())
}

/*
 * Validate the owner authentication configuration.
 *
 * Supported configurations:
 * - Passkey only
 * - Stellar signer only
 * - EVM signer only
 *
 * Exactly one owner-authentication method must be configured.
 */
// Keep this adapter aligned with the existing factory constructor arguments.
#[allow(clippy::too_many_arguments)]
pub fn write_create_account(
    e: &Env,
    challenge: BytesN<32>,

    passkey: Option<BytesN<65>>,
    passkey_sig: Option<PasskeySignature>,

    stellar_signer: Option<BytesN<32>>,
    stellar_address: Option<Address>,

    evm_signer: Option<BytesN<20>>,
    evm_sig: Option<EvmSignature>,

    bls_keys_pop: Vec<BlsKeyWithPoP>,
    guardians: Vec<Address>,
) -> Result<Address, AccountError> {
    /*
     * Validate the owner authentication configuration before deployment.
     *
     * Supported configurations:
     * - passkey only
     * - Stellar signer only
     * - EVM signer only
     *
     * This preserves your current mutually exclusive design.
     */
    match (
        &passkey,
        &passkey_sig,
        &stellar_signer,
        &stellar_address,
        &evm_signer,
        &evm_sig,
    ) {
        /*
         * Passkey-owned account.
         */
        (Some(_), Some(_), None, None, None, None) => {}

        /*
         * Native Stellar-owned account.
         *
         * The factory invocation must be authorized by the
         * Stellar account before deploying the account.
         */
        (None, None, Some(_), Some(stellar_address), None, None) => {
            stellar_address.require_auth();
        }

        /*
         * EVM-owned account.
         *
         * The account constructor verifies evm_sig as proof of
         * possession before storing evm_signer.
         */
        (None, None, None, None, Some(_), Some(_)) => {}

        /*
         * Reject incomplete, empty or mixed configurations.
         */
        _ => {
            return Err(AccountError::InvalidConfig);
        }
    };

    // Snapshot the factory's trusted RP configuration for every signer type.
    // This does not install a passkey or relax any proof-of-possession check.
    let rpid_hash = Some(read_rpid_hash(e)?);

    /*
     * Avoid unwrap() because a missing account WASM hash would
     * otherwise trap as WasmVm/InvalidAction.
     *
     * Adjust this line depending on whether read_account_wasm_hash()
     * returns Option or Result.
     */
    let wasm = read_account_wasm_hash(e).ok_or(AccountError::AccountVersionNotFound)?;

    let account_address = e
        .deployer()
        .with_current_contract(challenge.clone())
        .deploy_v2(
            wasm.clone(),
            (
                challenge,
                passkey,
                passkey_sig,
                rpid_hash,
                stellar_signer,
                stellar_address,
                evm_signer,
                evm_sig,
                bls_keys_pop,
                guardians,
                wasm,
                e.current_contract_address(),
            ),
        );

    Ok(account_address)
}
