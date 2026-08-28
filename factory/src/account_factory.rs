#![allow(unused)]
use crate::data::DataKey;
use socketfi_shared::{
    account_error::AccountError,
    bls::{g1_group_gen_point, is_g1_infinity},
    constants::{DST, MAX_BLS_KEYS, MIN_BLS_KEYS},
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
) -> Result<BytesN<32>, AccountError> {
    validate_network(e, &network)?;

    if read_creation_nonce_used(e, nonce) {
        return Err(AccountError::NonceAlreadyUsed);
    }
    let rp_id_hash = read_rpid_hash(e)?;
    let mut salt = Bytes::new(e);

    salt.append(&Bytes::from_slice(e, b"SOCKETFI_CREATE_ACCOUNT_POP"));
    salt.append(&network.to_xdr(e));
    salt.append(&rp_id_hash.to_xdr(e));
    salt.append(&nonce.to_xdr(e));

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
     *
     * This preserves your current mutually exclusive design.
     */
    let rpid_hash: Option<BytesN<32>> = match (
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
        (Some(_), Some(_), None, None, None, None) => Some(read_rpid_hash(e)?),

        /*
         * Native Stellar-owned account.
         *
         * The factory invocation must be authorized by the
         * Stellar account before deploying the account.
         */
        (None, None, Some(_), Some(stellar_address), None, None) => {
            stellar_address.require_auth();
            None
        }

        /*
         * EVM-owned account.
         *
         * The account constructor verifies evm_sig as proof of
         * possession before storing evm_signer.
         */
        (None, None, None, None, Some(_), Some(_)) => None,

        /*
         * Reject incomplete, empty or mixed configurations.
         */
        _ => {
            return Err(AccountError::InvalidConfig);
        }
    };

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
