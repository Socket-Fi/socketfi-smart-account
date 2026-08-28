use crate::{
    account_trait::AccountTrait,
    auth::{verify_bls_recovery_signature, verify_evm, verify_passkey, verify_stellar},
    guardians::{
        add_new_guardian, finalize_remove_guardian, guardian_can_approve_unpause,
        guardian_can_pause, is_paused, is_unpause_approved, schedule_remove_guardian,
        validate_guardians, write_guardians, write_paused, write_unpause_approved,
    },
    migrate::read_migration_required,
    session_policy::{
        authorize_session, create_session_policy, increment_session_epoch, read_session,
        remove_session, AccountAuth, SessionPolicy, SessionPolicyInput,
    },
    signer_management::{resolve_signer, signer_challenge},
    states::{
        clear_active_signers, is_initialized, read_evm_signer, read_factory, read_passkey,
        read_rpid_hash, read_stellar_signer, write_agg_bls_key, write_evm_signer, write_factory,
        write_installed_wasm_hash, write_passkey, write_rpid_hash, write_stellar_signer,
    },
    validation::{
        validate_auth_contexts, validate_stellar_address_key, validate_verify_bls_key_set_pop,
        verify_evm_pop, verify_passkey_pop,
    },
};

use socketfi_shared::{
    account_error::AccountError,
    constants::{MAX_AUTH_WINDOW_LEDGER, RECOVER_DOMAIN, ROTATION_DOMAIN},
    events,
    key_types::{AccountSigner, BlsKeyWithPoP, BlsSignature, EvmSignature, PasskeySignature},
    ttl::bump_instance,
};

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    crypto::Hash,
    Address, BytesN, Env, Vec,
};

#[contract]
pub struct Account;

#[contractimpl]
impl AccountTrait for Account {
    /// Initializes a newly deployed account.
    ///
    /// Validates the configured owner authentication methods,
    /// verifies passkey proof of possession when present,
    /// validates and authorizes the Stellar signer when present,
    /// verifies and aggregates the guardian BLS keys,
    /// validates the guardian configuration,
    /// and stores the initial account state.
    fn __constructor(
        env: Env,
        challenge: BytesN<32>,
        passkey: Option<BytesN<65>>,
        passkey_sig: Option<PasskeySignature>,
        rpid_hash: Option<BytesN<32>>,
        stellar_signer: Option<BytesN<32>>,
        stellar_address: Option<Address>,
        evm_signer: Option<BytesN<20>>,
        evm_sig: Option<EvmSignature>,
        bls_keys_pop: Vec<BlsKeyWithPoP>,
        guardians: Vec<Address>,
        wasm_hash: BytesN<32>,
        factory: Address,
    ) -> Result<(), AccountError> {
        if is_initialized(&env) {
            return Err(AccountError::AlreadyInitialized);
        }

        validate_guardians(&guardians)?;

        let passkey_configured: bool =
            passkey.is_some() && passkey_sig.is_some() && rpid_hash.is_some();

        let passkey_absent = passkey.is_none() && passkey_sig.is_none() && rpid_hash.is_none();

        let stellar_configured = stellar_signer.is_some() && stellar_address.is_some();

        let stellar_absent = stellar_signer.is_none() && stellar_address.is_none();

        let evm_configured = evm_signer.is_some() && evm_sig.is_some();

        let evm_absent = evm_signer.is_none() && evm_sig.is_none();

        if !passkey_configured && !passkey_absent {
            return Err(AccountError::InvalidConfig);
        }

        if !stellar_configured && !stellar_absent {
            return Err(AccountError::InvalidConfig);
        }

        if !evm_configured && !evm_absent {
            return Err(AccountError::InvalidConfig);
        }

        /*
         * Every SocketFi account must have at least one owner
         * authentication method.
         */
        if !passkey_configured && !stellar_configured && !evm_configured {
            return Err(AccountError::InvalidConfig);
        }

        /* Install passkey owner. */
        /* Install Stellar owner. */
        /* Install EVM owner. */
        match (passkey, passkey_sig, rpid_hash) {
            (Some(passkey), Some(passkey_sig), Some(rpid_hash)) => {
                verify_passkey_pop(
                    &env,
                    challenge.clone(),
                    passkey.clone(),
                    passkey_sig,
                    rpid_hash.clone(),
                )?;

                write_passkey(&env, &passkey);

                write_rpid_hash(&env, &rpid_hash);
            }

            (None, None, None) => {}

            _ => {
                return Err(AccountError::InvalidConfig);
            }
        }

        /*
         * Configure native Stellar ownership.
         */
        match (stellar_signer, stellar_address) {
            (Some(stellar_signer), Some(stellar_address)) => {
                validate_stellar_address_key(&stellar_address, &stellar_signer)?;

                write_stellar_signer(&env, &stellar_signer);
            }

            (None, None) => {}

            _ => {
                return Err(AccountError::InvalidConfig);
            }
        }

        /*
         * Install the EVM owner after verifying proof of possession.
         */
        match (evm_signer, evm_sig) {
            (Some(evm_signer), Some(evm_sig)) => {
                verify_evm_pop(&env, challenge.clone(), evm_signer.clone(), evm_sig)?;

                write_evm_signer(&env, &evm_signer);
            }

            (None, None) => {}

            _ => {
                return Err(AccountError::InvalidConfig);
            }
        }

        let bls_agg = validate_verify_bls_key_set_pop(&env, challenge, bls_keys_pop)?;

        write_agg_bls_key(&env, &bls_agg)?;

        write_guardians(&env, guardians);

        write_installed_wasm_hash(&env, &wasm_hash);
        write_factory(&env, &factory);

        write_paused(&env, false);

        write_unpause_approved(&env, false);

        Ok(())
    }

    fn rotate_account(
        env: Env,
        new_signer: AccountSigner,
        live_until_ledger: u32,
    ) -> Result<u64, AccountError> {
        /* Current owner authorizes this rotation. */
        env.current_contract_address().require_auth();

        let current_ledger = env.ledger().sequence();

        let latest_allowed = current_ledger
            .checked_add(MAX_AUTH_WINDOW_LEDGER)
            .ok_or(AccountError::ArithmeticOverflow)?;

        if live_until_ledger < current_ledger || live_until_ledger > latest_allowed {
            return Err(AccountError::InvalidConfig);
        }

        let commitment = resolve_signer(&new_signer);

        let challenge = signer_challenge(&env, live_until_ledger, &commitment, ROTATION_DOMAIN);

        /*
         * Remove the current signer before installing the replacement.
         * State changes are rolled back if installation fails.
         */
        clear_active_signers(&env);
        match &new_signer {
            AccountSigner::Passkey(input) => {
                let rpid_hash = read_rpid_hash(&env).ok_or(AccountError::RpidNotFound)?;

                verify_passkey_pop(
                    &env,
                    challenge.clone(),
                    input.public_key.clone(),
                    input.pop_signature.clone(),
                    rpid_hash,
                )?;

                write_passkey(&env, &input.public_key);
            }

            AccountSigner::Stellar(input) => {
                input.address.require_auth();
                validate_stellar_address_key(&input.address, &input.public_key)?;

                write_stellar_signer(&env, &input.public_key);
            }

            AccountSigner::Evm(input) => {
                verify_evm_pop(
                    &env,
                    challenge.clone(),
                    input.address.clone(),
                    input.pop_signature.clone(),
                )?;
                write_evm_signer(&env, &input.address);
            }
        }

        /*
         * Revoke sessions created by the previous signer.
         *
         * Existing session records do not need to be individually
         * removed; their old epoch makes them immediately invalid.
         */
        let new_session_epoch = increment_session_epoch(&env)?;

        events::AccountRotationEvent {
            commitment,
            live_until_ledger,
            new_session_epoch,
        }
        .publish(&env);

        Ok(new_session_epoch)
    }

    /*
     * All recovery authorization and replacement-signer proof-of-possession
     * checks have succeeded. Remove every existing active signer and install
     * exactly one replacement signer.
     *
     * Soroban execution is atomic: if installing the replacement fails or this
     * invocation returns an error, the signer removals are rolled back.
     * account-level recovery configuration, including the RP ID hash and
     * aggregated BLS recovery key, remains unchanged.
     */
    fn recover_account(
        env: Env,
        new_signer: AccountSigner,
        recovery_signature: BlsSignature,
        live_until_ledger: u32,
    ) -> Result<u64, AccountError> {
        let current_ledger = env.ledger().sequence();

        let latest_allowed = current_ledger
            .checked_add(MAX_AUTH_WINDOW_LEDGER)
            .ok_or(AccountError::ArithmeticOverflow)?;

        if live_until_ledger <= current_ledger || live_until_ledger > latest_allowed {
            return Err(AccountError::InvalidConfig);
        }

        let commitment = resolve_signer(&new_signer);

        let challenge = signer_challenge(&env, live_until_ledger, &commitment, RECOVER_DOMAIN);

        /* Verify guardian recovery authorization. */
        verify_bls_recovery_signature(&env, challenge.clone(), recovery_signature)?;

        /*
         * Then prove control of the replacement signer.
         * Every authorization check has succeeded. Atomically replace the
         * compromised or inaccessible signer.
         */
        clear_active_signers(&env);
        match &new_signer {
            AccountSigner::Passkey(input) => {
                let rpid_hash = read_rpid_hash(&env).ok_or(AccountError::RpidNotFound)?;

                verify_passkey_pop(
                    &env,
                    challenge.clone(),
                    input.public_key.clone(),
                    input.pop_signature.clone(),
                    rpid_hash,
                )?;

                write_passkey(&env, &input.public_key);
            }

            AccountSigner::Stellar(input) => {
                validate_stellar_address_key(&input.address, &input.public_key)?;

                input.address.require_auth();

                write_stellar_signer(&env, &input.public_key);
            }

            AccountSigner::Evm(input) => {
                verify_evm_pop(
                    &env,
                    challenge.clone(),
                    input.address.clone(),
                    input.pop_signature.clone(),
                )?;

                write_evm_signer(&env, &input.address);
            }
        }

        // Invalidate every session issued under the previous owner.
        let new_session_epoch = increment_session_epoch(&env)?;

        bump_instance(&env);

        events::AccountRecoveryEvent {
            commitment,
            live_until_ledger,
            new_session_epoch,
        }
        .publish(&env);

        Ok(new_session_epoch)
    }

    fn create_session(
        env: Env,
        input: SessionPolicyInput,
        delegate_pop: BytesN<64>,
    ) -> Result<BytesN<32>, AccountError> {
        env.current_contract_address().require_auth();
        create_session_policy(&env, input, delegate_pop)
    }

    fn revoke_session(env: Env, policy_id: BytesN<32>) -> Result<(), AccountError> {
        env.current_contract_address().require_auth();

        if !remove_session(&env, &policy_id) {
            return Err(AccountError::SessionNotFound);
        }

        Ok(())
    }

    fn migrate(env: Env) -> Result<(), AccountError> {
        env.current_contract_address().require_auth();

        let (required, wasm_hash) = read_migration_required(&env);

        if !required {
            return Err(AccountError::MigrationNotRequired);
        }

        env.deployer()
            .update_current_contract_wasm(wasm_hash.unwrap());

        bump_instance(&env);

        Ok(())
    }

    fn revoke_all_sessions(env: Env) -> Result<u64, AccountError> {
        env.current_contract_address().require_auth();

        let epoch = increment_session_epoch(&env)?;
        // env.events().publish((symbol_short!("sess_all"),), epoch);

        Ok(epoch)
    }

    /// Immediately pauses the account.
    ///
    /// Any authorized guardian may trigger a pause to protect the account.
    fn pause(env: Env, guardian: Address) -> Result<(), AccountError> {
        guardian.require_auth();

        if !guardian_can_pause(&env, &guardian) {
            return Err(AccountError::UnauthorizedGuardian);
        }

        if is_paused(&env) {
            return Ok(());
        }

        write_paused(&env, true);
        write_unpause_approved(&env, false);
        bump_instance(&env);

        Ok(())
    }

    /// Guardian approval to resume account activity.
    fn approve_unpause(env: Env, guardian: Address) -> Result<(), AccountError> {
        guardian.require_auth();

        if !guardian_can_approve_unpause(&env, &guardian) {
            return Err(AccountError::UnauthorizedGuardian);
        }

        if !is_paused(&env) {
            return Ok(());
        }

        write_unpause_approved(&env, true);
        bump_instance(&env);
        Ok(())
    }
    /// Removes the paused state after account authentication
    /// and guardian approval.
    fn unpause(env: Env) -> Result<(), AccountError> {
        env.current_contract_address().require_auth();

        if !is_paused(&env) {
            return Ok(());
        }

        if !is_unpause_approved(&env) {
            return Err(AccountError::UnpauseNotApproved);
        }

        write_paused(&env, false);
        write_unpause_approved(&env, false);

        Ok(())
    }

    /// Adds a new guardian to the account.
    fn add_guardian(env: Env, guardian: Address) -> Result<(), AccountError> {
        let account = env.current_contract_address();
        account.require_auth();
        if guardian == account {
            return Err(AccountError::InvalidGuardian);
        }

        bump_instance(&env);
        add_new_guardian(&env, guardian)
    }

    /// Returns whether the account is currently paused.
    fn is_paused(env: Env) -> bool {
        is_paused(&env)
    }

    // Begins a guardian removal process.
    ///
    /// Removal is delayed to provide a safety window.
    fn schedule_guardian_removal(env: Env, guardian: Address) -> Result<(), AccountError> {
        env.current_contract_address().require_auth();
        schedule_remove_guardian(&env, guardian)
    }

    /// Completes a previously scheduled guardian removal.
    fn finalize_guardian_removal(env: Env, guardian: Address) -> Result<(), AccountError> {
        bump_instance(&env);
        finalize_remove_guardian(&env, guardian)
    }

    fn get_session(env: Env, policy_id: BytesN<32>) -> Option<SessionPolicy> {
        read_session(&env, &policy_id)
    }

    /// Returns the currently registered passkey.
    fn get_passkey(env: Env) -> Option<BytesN<65>> {
        read_passkey(&env)
    }
    /// Returns whether migration is required and the target WASM hash.
    fn get_migration_required(env: Env) -> (bool, Option<BytesN<32>>) {
        read_migration_required(&env)
    }
    /// Returns the factory contract address.
    fn get_factory(env: Env) -> Option<Address> {
        read_factory(&env)
    }
}

#[contractimpl]
impl CustomAccountInterface for Account {
    type Signature = AccountAuth;
    type Error = AccountError;

    /// Soroban authentication entrypoint.
    ///
    /// Verifies owner or session authorization and validates
    /// the execution context for authenticated invocations.
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: AccountAuth,
        auth_contexts: Vec<Context>,
    ) -> Result<(), AccountError> {
        match signature {
            AccountAuth::Passkey(passkey_signature) => {
                if read_passkey(&env).is_none() {
                    return Err(AccountError::PasskeyNotFound);
                }

                validate_auth_contexts(&env, auth_contexts)?;
                verify_passkey(&env, signature_payload.into(), passkey_signature)?;
                Ok(())
            }

            AccountAuth::Stellar(stellar_signature) => {
                if read_stellar_signer(&env).is_none() {
                    return Err(AccountError::StellarSignerNotFound);
                }

                validate_auth_contexts(&env, auth_contexts)?;

                verify_stellar(&env, &signature_payload, stellar_signature)
            }

            AccountAuth::Evm(evm_signature) => {
                if read_evm_signer(&env).is_none() {
                    return Err(AccountError::EvmSignerNotFound);
                }

                /*
                 * Keep the same restrictions used for normal owner
                 * authentication. EVM auth must not bypass them.
                 */
                validate_auth_contexts(&env, auth_contexts)?;

                verify_evm(&env, &signature_payload, evm_signature)
            }

            AccountAuth::Session(session_authorization) => {
                if is_paused(&env) {
                    return Err(AccountError::AccountPaused);
                }

                authorize_session(
                    &env,
                    &signature_payload,
                    session_authorization,
                    auth_contexts,
                )
            }
        }
    }
}
