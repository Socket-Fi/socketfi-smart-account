use crate::{
    auth::{authorize_recovery, verify_passkey},
    guardians::{
        add_new_guardian, finalize_remove_guardian, guardian_can_approve_unpause,
        guardian_can_pause, is_paused, is_unpause_approved, schedule_remove_guardian,
        validate_guardians, write_guardians, write_paused, write_unpause_approved,
    },
    states::{
        is_initialized, read_passkey, read_rpid_hash, write_agg_bls_key, write_passkey,
        write_rpid_hash,
    },
    validation::{
        build_passkey_action_challenge, validate_auth_contexts, validate_verify_bls_key_set_pop,
        verify_passkey_pop,
    },
    wallet_trait::WalletTrait,
};

use socketfi_shared::{
    events,
    key_types::{BlsKeyWithPoP, PasskeySignature},
    wallet_error::WalletError,
};

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    Address, BytesN, Env, Vec,
};

const ROTATE_DOMAIN: &[u8] = b"SOCKETFI_ROTATE_PASSKEY_V1";
const RECOVER_DOMAIN: &[u8] = b"SOCKETFI_RECOVER_ACCOUNT_V1";

#[contract]
pub struct Wallet;

#[contractimpl]
impl WalletTrait for Wallet {
    /// Initializes a newly deployed wallet.
    ///
    /// Verifies the initial passkey and guardian configuration,
    /// aggregates the guardian BLS keys, and stores the wallet state.
    fn __constructor(
        env: Env,
        challenge: BytesN<32>,
        passkey: BytesN<65>,
        passkey_sig: PasskeySignature,
        rpid_hash: BytesN<32>,
        bls_keys_pop: Vec<BlsKeyWithPoP>,
        guardians: Vec<Address>,
    ) -> Result<(), WalletError> {
        if is_initialized(&env) {
            return Err(WalletError::AlreadyInitialized);
        }

        validate_guardians(&guardians)?;

        verify_passkey_pop(
            &env,
            challenge.clone(),
            passkey.clone(),
            passkey_sig,
            rpid_hash.clone(),
        )?;

        let bls_agg = validate_verify_bls_key_set_pop(&env, challenge, bls_keys_pop)?;

        write_passkey(&env, passkey);
        write_rpid_hash(&env, &rpid_hash);
        write_agg_bls_key(&env, bls_agg)?;
        write_guardians(&env, guardians);
        write_paused(&env, false);
        write_unpause_approved(&env, false);

        Ok(())
    }

    /// Rotates the wallet's passkey.
    ///
    /// Requires normal wallet authentication and proof of possession
    /// for the new passkey before replacing the stored credential.
    fn rotate_passkey(
        env: Env,
        new_passkey: BytesN<65>,
        new_passkey_pop_sig: PasskeySignature,
    ) -> Result<(), WalletError> {
        env.current_contract_address().require_auth();

        let rpid_hash = read_rpid_hash(&env).ok_or(WalletError::RpidNotFound)?;

        let challenge = build_passkey_action_challenge(&env, ROTATE_DOMAIN, new_passkey.clone());

        verify_passkey_pop(
            &env,
            challenge,
            new_passkey.clone(),
            new_passkey_pop_sig,
            rpid_hash,
        )?;

        write_passkey(&env, new_passkey.clone());

        events::PasskeyRotationEvent {
            wallet: env.current_contract_address(),
            new_passkey,
        }
        .publish(&env);

        Ok(())
    }

    /// Recovers the wallet using the stored aggregate BLS recovery key.
    ///
    /// Off chain verification of account ownership
    /// A new passkey is installed only after:
    /// - the new passkey proves possession, and
    /// - the aggregate BLS recovery signature is verified.
    fn recover_account(
        env: Env,
        new_passkey: BytesN<65>,
        new_passkey_pop_sig: PasskeySignature,
        agg_bls_sig: BytesN<192>,
    ) -> Result<(), WalletError> {
        let rpid_hash = read_rpid_hash(&env).ok_or(WalletError::RpidNotFound)?;

        let challenge = build_passkey_action_challenge(&env, RECOVER_DOMAIN, new_passkey.clone());

        verify_passkey_pop(
            &env,
            challenge.clone(),
            new_passkey.clone(),
            new_passkey_pop_sig,
            rpid_hash,
        )?;

        authorize_recovery(env.clone(), challenge, agg_bls_sig)?;

        write_passkey(&env, new_passkey.clone());

        events::WalletRecoveryEvent {
            wallet: env.current_contract_address(),
            new_passkey,
        }
        .publish(&env);

        Ok(())
    }

    /// Immediately pauses the wallet.
    ///
    /// Any authorized guardian may trigger a pause to protect the account.
    fn pause(env: Env, guardian: Address) -> Result<(), WalletError> {
        guardian.require_auth();

        if !guardian_can_pause(&env, &guardian) {
            return Err(WalletError::UnauthorizedGuardian);
        }

        if is_paused(&env) {
            return Ok(());
        }

        write_paused(&env, true);
        write_unpause_approved(&env, false);

        Ok(())
    }

    /// Guardian approval to resume wallet activity.
    fn approve_unpause(env: Env, guardian: Address) -> Result<(), WalletError> {
        guardian.require_auth();

        if !guardian_can_approve_unpause(&env, &guardian) {
            return Err(WalletError::UnauthorizedGuardian);
        }

        if !is_paused(&env) {
            return Ok(());
        }

        write_unpause_approved(&env, true);

        Ok(())
    }
    /// Removes the paused state after wallet authentication
    /// and guardian approval.
    fn unpause(env: Env) -> Result<(), WalletError> {
        env.current_contract_address().require_auth();

        if !is_paused(&env) {
            return Ok(());
        }

        if !is_unpause_approved(&env) {
            return Err(WalletError::UnpauseNotApproved);
        }

        write_paused(&env, false);
        write_unpause_approved(&env, false);

        Ok(())
    }

    /// Adds a new guardian to the wallet.
    fn add_guardian(env: Env, guardian: Address) -> Result<(), WalletError> {
        let wallet = env.current_contract_address();
        wallet.require_auth();
        if guardian == wallet {
            return Err(WalletError::InvalidGuardian);
        }

        add_new_guardian(&env, guardian)
    }

    /// Returns whether the wallet is currently paused.
    fn is_paused(env: Env) -> bool {
        is_paused(&env)
    }

    // Begins a guardian removal process.
    ///
    /// Removal is delayed to provide a safety window.
    fn schedule_guardian_removal(env: Env, guardian: Address) -> Result<(), WalletError> {
        env.current_contract_address().require_auth();
        schedule_remove_guardian(&env, guardian)
    }

    /// Completes a previously scheduled guardian removal.
    fn finalize_guardian_removal(env: Env, guardian: Address) -> Result<(), WalletError> {
        finalize_remove_guardian(&env, guardian)
    }

    /// Returns the currently registered passkey.
    fn get_passkey(env: Env) -> Option<BytesN<65>> {
        read_passkey(&env)
    }
}

#[contractimpl]
impl CustomAccountInterface for Wallet {
    type Signature = PasskeySignature;
    type Error = WalletError;

    /// Soroban authentication entrypoint.
    ///
    /// Every contract invocation requiring wallet authorization
    /// passes through this method. It validates the execution
    /// context and verifies the passkey signature over the
    /// transaction payload.
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: PasskeySignature,
        auth_contexts: Vec<Context>,
    ) -> Result<(), WalletError> {
        if read_passkey(&env).is_none() {
            return Err(WalletError::PasskeyNotFound);
        }

        validate_auth_contexts(&env, auth_contexts)?;

        verify_passkey(&env, signature_payload.into(), signature)?;

        Ok(())
    }
}
