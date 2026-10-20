use crate::{
    account_trait::AccountTrait,
    auth::{verify_bls_recovery_signature, verify_evm, verify_passkey, verify_stellar},
    guardians::{
        add_new_guardian, finalize_remove_guardian, guardian_can_approve_unpause,
        guardian_can_pause, is_paused, is_unpause_approved, read_guardians,
        schedule_remove_guardian, validate_guardians, write_guardians, write_paused,
        write_unpause_approved,
    },
    migrate::read_migration_required,
    session_policy::{
        authorize_session, create_session_policy, increment_session_epoch, read_session,
        read_session_epoch, remove_session, AccountAuth, SessionPolicy, SessionPolicyInput,
    },
    signer_management::{
        active_binding_types, binding_challenge, binding_commitment, binding_count, binding_exists,
        migration_challenge, read_bindings, remove_binding as remove_binding_state, resolve_signer,
        signer_type, validate_auth_window, verify_and_install_signer, verify_approval_set,
    },
    states::{
        increment_auth_config_nonce, is_initialized, read_auth_config_nonce, read_evm_signer,
        read_factory, read_passkey, read_stellar_signer, write_agg_bls_key,
        write_auth_config_nonce, write_evm_signer, write_factory, write_installed_wasm_hash,
        write_passkey, write_rpid_hash, write_stellar_signer,
    },
    validation::{
        validate_auth_contexts, validate_stellar_address_key, validate_verify_bls_key_set_pop,
        verify_evm_pop, verify_passkey_pop,
    },
};

use socketfi_shared::{
    account_error::AccountError,
    constants::{
        ADD_BINDING_DOMAIN, BLS_RECOVER_BINDING_DOMAIN, PEER_RECOVER_BINDING_DOMAIN,
        REMOVE_BINDING_DOMAIN, ROTATE_BINDING_DOMAIN,
    },
    events,
    key_types::{
        AccountSigner, AuthBindings, BindingChangeResult, BindingType, BlsKeyWithPoP, BlsSignature,
        EvmSignature, GuardianInfo, OwnerSignature, PasskeySignature,
    },
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
        for guardian in guardians.iter() {
            if guardian == env.current_contract_address() {
                return Err(AccountError::InvalidGuardian);
            }
        }

        // RP configuration belongs to the account, not its initial signer.
        // Keep the optional ABI field, but require it for every new account.
        let rpid_hash = rpid_hash.ok_or(AccountError::RpidNotFound)?;

        let passkey_configured = passkey.is_some() && passkey_sig.is_some();
        let passkey_absent = passkey.is_none() && passkey_sig.is_none();

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
        let configured_count = u32::from(passkey_configured)
            + u32::from(stellar_configured)
            + u32::from(evm_configured);
        if configured_count != 1 {
            return Err(AccountError::InvalidConfig);
        }

        /* Install passkey owner. */
        /* Install Stellar owner. */
        /* Install EVM owner. */
        match (passkey, passkey_sig) {
            (Some(passkey), Some(passkey_sig)) => {
                verify_passkey_pop(
                    &env,
                    challenge.clone(),
                    passkey.clone(),
                    passkey_sig,
                    rpid_hash.clone(),
                )?;

                write_passkey(&env, &passkey);
            }

            (None, None) => {}

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
        write_rpid_hash(&env, &rpid_hash);

        write_guardians(&env, guardians);

        write_installed_wasm_hash(&env, &wasm_hash);
        write_factory(&env, &factory);

        write_paused(&env, false);

        write_unpause_approved(&env, false);
        write_auth_config_nonce(&env, 0);
        bump_instance(&env);

        Ok(())
    }

    fn add_binding(
        env: Env,
        new_signer: AccountSigner,
        approvals: Vec<OwnerSignature>,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError> {
        if is_paused(&env) {
            return Err(AccountError::AccountPaused);
        }
        validate_auth_window(&env, live_until_ledger)?;
        let target = signer_type(&new_signer);
        if binding_exists(&env, &target) {
            return Err(AccountError::BindingAlreadyExists);
        }
        let replacement = resolve_signer(&new_signer);
        let challenge = binding_challenge(
            &env,
            ADD_BINDING_DOMAIN,
            target,
            None,
            Some(replacement.clone()),
            live_until_ledger,
        );
        verify_approval_set(&env, &challenge, approvals, active_binding_types(&env))?;
        verify_and_install_signer(&env, &new_signer, challenge)?;
        let auth_config_nonce = increment_auth_config_nonce(&env)?;
        let session_epoch = read_session_epoch(&env);
        bump_instance(&env);
        events::BindingAddedEvent {
            binding_type: target,
            commitment: replacement,
            auth_config_nonce,
        }
        .publish(&env);
        Ok(BindingChangeResult {
            auth_config_nonce,
            session_epoch,
        })
    }

    fn rotate_binding(
        env: Env,
        new_signer: AccountSigner,
        approval: OwnerSignature,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError> {
        if is_paused(&env) {
            return Err(AccountError::AccountPaused);
        }
        validate_auth_window(&env, live_until_ledger)?;
        let target = signer_type(&new_signer);
        let current = binding_commitment(&env, &target).ok_or(AccountError::BindingNotFound)?;
        let replacement = resolve_signer(&new_signer);
        if current == replacement {
            return Err(AccountError::InvalidConfig);
        }
        let challenge = binding_challenge(
            &env,
            ROTATE_BINDING_DOMAIN,
            target,
            Some(current.clone()),
            Some(replacement.clone()),
            live_until_ledger,
        );
        let mut required = Vec::new(&env);
        required.push_back(target);
        let mut approvals = Vec::new(&env);
        approvals.push_back(approval);
        verify_approval_set(&env, &challenge, approvals, required)?;
        remove_binding_state(&env, &target);
        verify_and_install_signer(&env, &new_signer, challenge)?;
        let auth_config_nonce = increment_auth_config_nonce(&env)?;
        let session_epoch = increment_session_epoch(&env)?;
        bump_instance(&env);
        events::BindingRotatedEvent {
            binding_type: target,
            previous: current,
            replacement,
            auth_config_nonce,
            session_epoch,
        }
        .publish(&env);
        Ok(BindingChangeResult {
            auth_config_nonce,
            session_epoch,
        })
    }

    fn remove_binding(
        env: Env,
        binding_type: BindingType,
        approval: OwnerSignature,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError> {
        if is_paused(&env) {
            return Err(AccountError::AccountPaused);
        }
        validate_auth_window(&env, live_until_ledger)?;
        if binding_count(&env) <= 1 {
            return Err(AccountError::LastBindingRemoval);
        }
        let current =
            binding_commitment(&env, &binding_type).ok_or(AccountError::BindingNotFound)?;
        let challenge = binding_challenge(
            &env,
            REMOVE_BINDING_DOMAIN,
            binding_type,
            Some(current.clone()),
            None,
            live_until_ledger,
        );
        let mut required = Vec::new(&env);
        required.push_back(binding_type);
        let mut approvals = Vec::new(&env);
        approvals.push_back(approval);
        verify_approval_set(&env, &challenge, approvals, required)?;
        remove_binding_state(&env, &binding_type);
        let auth_config_nonce = increment_auth_config_nonce(&env)?;
        let session_epoch = increment_session_epoch(&env)?;
        bump_instance(&env);
        events::BindingRemovedEvent {
            binding_type,
            previous: current,
            auth_config_nonce,
            session_epoch,
        }
        .publish(&env);
        Ok(BindingChangeResult {
            auth_config_nonce,
            session_epoch,
        })
    }

    fn recover_binding_with_bindings(
        env: Env,
        new_signer: AccountSigner,
        approvals: Vec<OwnerSignature>,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError> {
        validate_auth_window(&env, live_until_ledger)?;
        if binding_count(&env) != 3 {
            return Err(AccountError::PeerRecoveryUnavailable);
        }
        let target = signer_type(&new_signer);
        let current = binding_commitment(&env, &target).ok_or(AccountError::BindingNotFound)?;
        let replacement = resolve_signer(&new_signer);
        if current == replacement {
            return Err(AccountError::InvalidConfig);
        }
        let challenge = binding_challenge(
            &env,
            PEER_RECOVER_BINDING_DOMAIN,
            target,
            Some(current.clone()),
            Some(replacement.clone()),
            live_until_ledger,
        );
        let mut required = Vec::new(&env);
        for kind in active_binding_types(&env).iter() {
            if kind != target {
                required.push_back(kind);
            }
        }
        verify_approval_set(&env, &challenge, approvals, required)?;
        remove_binding_state(&env, &target);
        verify_and_install_signer(&env, &new_signer, challenge)?;
        let auth_config_nonce = increment_auth_config_nonce(&env)?;
        let session_epoch = increment_session_epoch(&env)?;
        bump_instance(&env);
        events::BindingRecoveredEvent {
            binding_type: target,
            previous: current,
            replacement,
            via_bls: false,
            auth_config_nonce,
            session_epoch,
        }
        .publish(&env);
        Ok(BindingChangeResult {
            auth_config_nonce,
            session_epoch,
        })
    }

    fn recover_binding_bls(
        env: Env,
        new_signer: AccountSigner,
        recovery_signature: BlsSignature,
        live_until_ledger: u32,
    ) -> Result<BindingChangeResult, AccountError> {
        validate_auth_window(&env, live_until_ledger)?;
        let target = signer_type(&new_signer);
        let current = binding_commitment(&env, &target).ok_or(AccountError::BindingNotFound)?;
        let replacement = resolve_signer(&new_signer);
        if current == replacement {
            return Err(AccountError::InvalidConfig);
        }
        let challenge = binding_challenge(
            &env,
            BLS_RECOVER_BINDING_DOMAIN,
            target,
            Some(current.clone()),
            Some(replacement.clone()),
            live_until_ledger,
        );
        verify_bls_recovery_signature(&env, challenge.clone(), recovery_signature)?;
        remove_binding_state(&env, &target);
        verify_and_install_signer(&env, &new_signer, challenge)?;
        let auth_config_nonce = increment_auth_config_nonce(&env)?;
        let session_epoch = increment_session_epoch(&env)?;
        bump_instance(&env);
        events::BindingRecoveredEvent {
            binding_type: target,
            previous: current,
            replacement,
            via_bls: true,
            auth_config_nonce,
            session_epoch,
        }
        .publish(&env);
        Ok(BindingChangeResult {
            auth_config_nonce,
            session_epoch,
        })
    }

    fn create_session(
        env: Env,
        input: SessionPolicyInput,
        delegate_pop: BytesN<64>,
    ) -> Result<BytesN<32>, AccountError> {
        env.current_contract_address().require_auth();
        let policy_id = create_session_policy(&env, input, delegate_pop)?;
        bump_instance(&env);
        Ok(policy_id)
    }

    fn revoke_session(env: Env, policy_id: BytesN<32>) -> Result<(), AccountError> {
        env.current_contract_address().require_auth();

        if !remove_session(&env, &policy_id) {
            return Err(AccountError::SessionNotFound);
        }

        events::SessionRevokedEvent { policy_id }.publish(&env);
        bump_instance(&env);

        Ok(())
    }

    fn migrate(
        env: Env,
        approvals: Vec<OwnerSignature>,
        live_until_ledger: u32,
    ) -> Result<(), AccountError> {
        if is_paused(&env) {
            return Err(AccountError::AccountPaused);
        }
        validate_auth_window(&env, live_until_ledger)?;
        let (required, wasm_hash) = read_migration_required(&env)?;

        if !required {
            return Err(AccountError::MigrationNotRequired);
        }

        let wasm_hash = wasm_hash.ok_or(AccountError::AccountVersionNotFound)?;
        let challenge = migration_challenge(&env, &wasm_hash, live_until_ledger);
        verify_approval_set(&env, &challenge, approvals, active_binding_types(&env))?;
        let auth_config_nonce = increment_auth_config_nonce(&env)?;
        let session_epoch = increment_session_epoch(&env)?;
        write_installed_wasm_hash(&env, &wasm_hash);
        env.deployer()
            .update_current_contract_wasm(wasm_hash.clone());

        bump_instance(&env);
        events::AccountMigratedEvent {
            wasm: wasm_hash,
            auth_config_nonce,
            session_epoch,
        }
        .publish(&env);

        Ok(())
    }

    fn revoke_all_sessions(env: Env) -> Result<u64, AccountError> {
        env.current_contract_address().require_auth();

        let epoch = increment_session_epoch(&env)?;
        events::AllSessionsRevokedEvent { epoch }.publish(&env);
        bump_instance(&env);

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
        events::AccountPausedEvent { guardian }.publish(&env);

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
        events::UnpauseApprovedEvent { guardian }.publish(&env);
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
        bump_instance(&env);
        events::AccountUnpausedEvent {}.publish(&env);

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
        add_new_guardian(&env, guardian.clone())?;
        events::GuardianAddedEvent { guardian }.publish(&env);
        Ok(())
    }

    /// Returns whether the account is currently paused.
    fn is_paused(env: Env) -> bool {
        bump_instance(&env);
        is_paused(&env)
    }

    // Begins a guardian removal process.
    ///
    /// Removal is delayed to provide a safety window.
    fn schedule_guardian_removal(env: Env, guardian: Address) -> Result<(), AccountError> {
        env.current_contract_address().require_auth();
        let removal_ledger = schedule_remove_guardian(&env, guardian.clone())?;
        bump_instance(&env);
        events::GuardianRemovalScheduledEvent {
            guardian,
            removal_ledger,
        }
        .publish(&env);
        Ok(())
    }

    /// Completes a previously scheduled guardian removal.
    fn finalize_guardian_removal(env: Env, guardian: Address) -> Result<(), AccountError> {
        bump_instance(&env);
        if finalize_remove_guardian(&env, guardian.clone())? {
            events::GuardianRemovedEvent { guardian }.publish(&env);
        }
        Ok(())
    }

    fn get_session(env: Env, policy_id: BytesN<32>) -> Option<SessionPolicy> {
        bump_instance(&env);
        read_session(&env, &policy_id)
    }
    fn get_bindings(env: Env) -> AuthBindings {
        bump_instance(&env);
        read_bindings(&env)
    }
    fn get_auth_config_nonce(env: Env) -> u64 {
        bump_instance(&env);
        read_auth_config_nonce(&env)
    }
    fn get_session_epoch(env: Env) -> u64 {
        bump_instance(&env);
        read_session_epoch(&env)
    }
    fn get_guardians(env: Env) -> Vec<GuardianInfo> {
        bump_instance(&env);
        read_guardians(&env)
    }
    fn get_migration_challenge(
        env: Env,
        live_until_ledger: u32,
    ) -> Result<(BytesN<32>, BytesN<32>), AccountError> {
        validate_auth_window(&env, live_until_ledger)?;
        let (required, wasm) = read_migration_required(&env)?;
        if !required {
            return Err(AccountError::MigrationNotRequired);
        }
        let wasm = wasm.ok_or(AccountError::AccountVersionNotFound)?;
        let challenge = migration_challenge(&env, &wasm, live_until_ledger);
        bump_instance(&env);
        Ok((wasm, challenge))
    }

    /// Returns the currently registered passkey.
    fn get_passkey(env: Env) -> Option<BytesN<65>> {
        bump_instance(&env);
        read_passkey(&env)
    }
    /// Returns whether migration is required and the target WASM hash.
    fn get_migration_required(env: Env) -> Result<(bool, Option<BytesN<32>>), AccountError> {
        bump_instance(&env);
        read_migration_required(&env)
    }
    /// Returns the factory contract address.
    fn get_factory(env: Env) -> Option<Address> {
        bump_instance(&env);
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
        bump_instance(&env);
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
