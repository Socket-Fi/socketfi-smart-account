use soroban_sdk::{xdr::ToXdr, Bytes, BytesN, Env, Vec};

use crate::{
    auth::verify_owner_signature,
    states::{
        read_auth_config_nonce, read_evm_signer, read_passkey, read_stellar_signer,
        write_evm_signer, write_passkey, write_stellar_signer, DataKey,
    },
    validation::{verify_evm_pop, verify_passkey_pop, verify_stellar_pop},
};
use socketfi_shared::{
    account_error::AccountError,
    constants::MAX_AUTH_WINDOW_LEDGER,
    key_types::{AccountCommitment, AccountSigner, AuthBindings, BindingType, OwnerSignature},
};

pub fn resolve_signer(signer: &AccountSigner) -> AccountCommitment {
    match signer {
        AccountSigner::Passkey(input) => AccountCommitment::Passkey(input.public_key.clone()),

        AccountSigner::Stellar(input) => AccountCommitment::Stellar(input.public_key.clone()),

        AccountSigner::Evm(input) => AccountCommitment::Evm(input.address.clone()),
    }
}

pub fn signer_type(signer: &AccountSigner) -> BindingType {
    match signer {
        AccountSigner::Passkey(_) => BindingType::Passkey,
        AccountSigner::Stellar(_) => BindingType::Stellar,
        AccountSigner::Evm(_) => BindingType::Evm,
    }
}

pub fn read_bindings(env: &Env) -> AuthBindings {
    AuthBindings {
        passkey: read_passkey(env),
        stellar: read_stellar_signer(env),
        evm: read_evm_signer(env),
    }
}

pub fn binding_count(env: &Env) -> u32 {
    let bindings = read_bindings(env);
    u32::from(bindings.passkey.is_some())
        + u32::from(bindings.stellar.is_some())
        + u32::from(bindings.evm.is_some())
}

pub fn binding_exists(env: &Env, binding_type: &BindingType) -> bool {
    binding_commitment(env, binding_type).is_some()
}

pub fn binding_commitment(env: &Env, binding_type: &BindingType) -> Option<AccountCommitment> {
    match binding_type {
        BindingType::Passkey => read_passkey(env).map(AccountCommitment::Passkey),
        BindingType::Stellar => read_stellar_signer(env).map(AccountCommitment::Stellar),
        BindingType::Evm => read_evm_signer(env).map(AccountCommitment::Evm),
    }
}

pub fn active_binding_types(env: &Env) -> Vec<BindingType> {
    let mut result = Vec::new(env);
    if read_passkey(env).is_some() {
        result.push_back(BindingType::Passkey);
    }
    if read_stellar_signer(env).is_some() {
        result.push_back(BindingType::Stellar);
    }
    if read_evm_signer(env).is_some() {
        result.push_back(BindingType::Evm);
    }
    result
}

pub fn validate_auth_window(env: &Env, live_until_ledger: u32) -> Result<(), AccountError> {
    let current = env.ledger().sequence();
    let latest = current
        .checked_add(MAX_AUTH_WINDOW_LEDGER)
        .ok_or(AccountError::ArithmeticOverflow)?;
    if live_until_ledger <= current || live_until_ledger > latest {
        return Err(AccountError::InvalidAuthWindow);
    }
    Ok(())
}

fn append_binding_type(payload: &mut Bytes, binding_type: &BindingType) {
    payload.push_back(match binding_type {
        BindingType::Passkey => 0,
        BindingType::Stellar => 1,
        BindingType::Evm => 2,
    });
}

fn commitment_hash(env: &Env, commitment: &AccountCommitment) -> BytesN<32> {
    let mut payload = Bytes::new(env);
    match commitment {
        AccountCommitment::Passkey(value) => {
            payload.push_back(0);
            payload.append(&value.clone().into());
        }
        AccountCommitment::Stellar(value) => {
            payload.push_back(1);
            payload.append(&value.clone().into());
        }
        AccountCommitment::Evm(value) => {
            payload.push_back(2);
            payload.append(&value.clone().into());
        }
    }
    env.crypto().sha256(&payload).into()
}

fn append_optional_commitment(
    env: &Env,
    payload: &mut Bytes,
    commitment: Option<AccountCommitment>,
) {
    match commitment {
        Some(value) => {
            payload.push_back(1);
            payload.append(&commitment_hash(env, &value).into());
        }
        None => {
            payload.push_back(0);
            payload.append(&Bytes::from_slice(env, &[0; 32]));
        }
    }
}

pub fn binding_challenge(
    env: &Env,
    domain: &[u8],
    target: BindingType,
    current: Option<AccountCommitment>,
    replacement: Option<AccountCommitment>,
    live_until_ledger: u32,
) -> BytesN<32> {
    let mut payload = Bytes::from_slice(env, domain);
    payload.append(&env.ledger().network_id().into());
    payload.append(&env.current_contract_address().to_xdr(env));
    append_binding_type(&mut payload, &target);
    append_optional_commitment(env, &mut payload, current);
    append_optional_commitment(env, &mut payload, replacement);
    payload.append(&Bytes::from_slice(
        env,
        &read_auth_config_nonce(env).to_be_bytes(),
    ));
    payload.append(&Bytes::from_slice(env, &live_until_ledger.to_be_bytes()));
    env.crypto().sha256(&payload).into()
}

pub fn migration_challenge(env: &Env, wasm: &BytesN<32>, live_until_ledger: u32) -> BytesN<32> {
    let mut payload = Bytes::from_slice(env, socketfi_shared::constants::MIGRATE_ACCOUNT_DOMAIN);
    payload.append(&env.ledger().network_id().into());
    payload.append(&env.current_contract_address().to_xdr(env));
    payload.append(&wasm.clone().into());
    payload.append(&Bytes::from_slice(
        env,
        &read_auth_config_nonce(env).to_be_bytes(),
    ));
    payload.append(&Bytes::from_slice(env, &live_until_ledger.to_be_bytes()));
    env.crypto().sha256(&payload).into()
}

fn signature_type(signature: &OwnerSignature) -> BindingType {
    match signature {
        OwnerSignature::Passkey(_) => BindingType::Passkey,
        OwnerSignature::Stellar(_) => BindingType::Stellar,
        OwnerSignature::Evm(_) => BindingType::Evm,
    }
}

fn contains_type(types: &Vec<BindingType>, target: &BindingType) -> bool {
    for value in types.iter() {
        if value == *target {
            return true;
        }
    }
    false
}

pub fn verify_approval_set(
    env: &Env,
    challenge: &BytesN<32>,
    approvals: Vec<OwnerSignature>,
    required: Vec<BindingType>,
) -> Result<(), AccountError> {
    if approvals.len() != required.len() {
        return Err(AccountError::InsufficientBindingApprovals);
    }

    let mut seen = Vec::new(env);
    for approval in approvals.iter() {
        let kind = signature_type(&approval);
        if contains_type(&seen, &kind) {
            return Err(AccountError::DuplicateApproval);
        }
        if !contains_type(&required, &kind) {
            return Err(AccountError::InvalidApprovalSet);
        }
        let verified_kind = verify_owner_signature(env, challenge.clone(), approval)?;
        if verified_kind != kind {
            return Err(AccountError::InvalidApprovalSet);
        }
        seen.push_back(kind);
    }

    for required_kind in required.iter() {
        if !contains_type(&seen, &required_kind) {
            return Err(AccountError::InsufficientBindingApprovals);
        }
    }
    Ok(())
}

pub fn verify_and_install_signer(
    env: &Env,
    signer: &AccountSigner,
    challenge: BytesN<32>,
) -> Result<AccountCommitment, AccountError> {
    match signer {
        AccountSigner::Passkey(input) => {
            let rpid_hash = crate::states::read_rpid_hash(env).ok_or(AccountError::RpidNotFound)?;
            verify_passkey_pop(
                env,
                challenge,
                input.public_key.clone(),
                input.pop_signature.clone(),
                rpid_hash,
            )?;
            write_passkey(env, &input.public_key);
        }
        AccountSigner::Stellar(input) => {
            verify_stellar_pop(
                env,
                challenge,
                input.public_key.clone(),
                input.address.clone(),
                input.pop_signature.clone(),
            )?;
            write_stellar_signer(env, &input.public_key);
        }
        AccountSigner::Evm(input) => {
            verify_evm_pop(
                env,
                challenge,
                input.address.clone(),
                input.pop_signature.clone(),
            )?;
            write_evm_signer(env, &input.address);
        }
    }
    Ok(resolve_signer(signer))
}

pub fn remove_binding(env: &Env, binding_type: &BindingType) {
    let storage = env.storage().instance();
    match binding_type {
        BindingType::Passkey => storage.remove(&DataKey::Passkey),
        BindingType::Stellar => storage.remove(&DataKey::StellarSigner),
        BindingType::Evm => storage.remove(&DataKey::EvmSigner),
    }
}
