use soroban_sdk::{
    contract, contractimpl, xdr::ToXdr, Address, Bytes, BytesN, Env, Map, String, Vec,
};

use crate::{
    contract_trait::RegistryTrait,
    registry::{
        read_passkey_wallet_map, read_userid_wallet_map, remove_userid_wallet_map,
        write_passkey_wallet_map, write_userid_wallet_map,
    },
    registry_managers::{
        read_is_registry_manager, require_registry_manager, write_add_registry_manager,
        write_remove_registry_manager,
    },
    validators::{
        read_is_validator, read_threshold, read_validators, write_add_validator,
        write_remove_validator,
    },
};
use socketfi_access::access::{authenticate_admin, has_admin, read_factory, write_admin};
use socketfi_shared::{
    events,
    registry_errors::RegistryError,
    registry_types::{SocialPlatform, ValidatorSignature},
    utils::validate_userid,
};
use upgrade::{
    cancel_upgrade_proposal, create_upgrade_proposal, errors::UpgradeError, execute_upgrade,
    upgrade_add_voter, upgrade_remove_voter, write_cast_vote,
};

/// Identity registry contract.
///
/// Notes:
/// - Manages wallet bindings for user identities and passkeys.
/// - Uses validator signatures for identity verification.
/// - Includes admin control and upgrade governance.
#[contract]
pub struct Registry;

#[contractimpl]
impl RegistryTrait for Registry {
    // initialization

    /// Initialize registry.
    ///
    /// Notes:
    /// - Sets initial admin.
    /// - Intended to run once.
    fn __constructor(e: Env, admin: Address) -> Result<(), UpgradeError> {
        if has_admin(&e) {
            return Err(UpgradeError::AlreadyInitialized);
        }

        write_admin(&e, &admin);

        Ok(())
    }

    /// Add registry manager.
    ///
    /// Authorization:
    /// - Admin only.
    ///
    /// Security model:
    /// - Registry managers are recovery operators.
    /// - They may unlink stale or compromised identity bindings.
    /// - They cannot create, overwrite, or rebind identity mappings.
    fn add_manager(e: Env, manager: Address) -> Result<(), RegistryError> {
        authenticate_admin(&e);

        if read_is_registry_manager(&e, manager.clone()) {
            return Ok(());
        }

        write_add_registry_manager(&e, manager);

        Ok(())
    }

    /// Remove registry manager.
    ///
    /// Authorization:
    /// - Admin only.
    ///
    /// Security model:
    /// - Revokes the manager's ability to perform future recovery unlink actions.
    /// - Existing identity bindings are not changed.
    fn remove_manager(e: Env, manager: Address) -> Result<(), RegistryError> {
        authenticate_admin(&e);

        if !read_is_registry_manager(&e, manager.clone()) {
            return Ok(());
        }

        write_remove_registry_manager(&e, manager);

        Ok(())
    }

    // identity core

    /// Set passkey -> wallet mapping.
    ///
    /// Notes:
    /// - Factory only.
    /// - Used for wallet lookup by passkey.
    fn set_passkey_wallet_map(
        e: Env,
        passkey: BytesN<65>,
        wallet: Address,
    ) -> Result<(), RegistryError> {
        let factory = read_factory(&e).ok_or(RegistryError::FactoryNotSet)?;
        factory.require_auth();
        write_passkey_wallet_map(&e, passkey.clone(), wallet.clone())?;

        events::PasskeyMapEvent { wallet, passkey }.publish(&e);

        Ok(())
    }

    /// Verify identity and bind wallet.
    ///
    /// Notes:
    /// - Requires wallet authorization.
    /// - Validates platform, user id, and validator signatures.
    /// - Writes `(platform, user_id) -> wallet` mapping on success.
    fn set_id_wallet_map(
        e: Env,
        wallet: Address,
        user_id: String,
        platform_str: String,
        signatures: Vec<ValidatorSignature>,
    ) -> Result<(), RegistryError> {
        wallet.require_auth();

        let platform = SocialPlatform::is_platform_supported(platform_str)?;
        validate_userid(user_id.clone())?;

        let threshold = read_threshold(&e);
        if threshold == 0 {
            return Err(RegistryError::InvalidThreshold);
        }

        if signatures.len() as u32 != threshold {
            return Err(RegistryError::IncorrectNumberOfSignatures);
        }

        let mut seen = Map::<BytesN<32>, bool>::new(&e);

        for s in signatures.iter() {
            let validator = s.validator.clone();

            if !read_is_validator(&e, validator.clone()) {
                return Err(RegistryError::NotValidator);
            }

            if seen.get(validator.clone()).unwrap_or(false) {
                return Err(RegistryError::DuplicateValidator);
            }

            seen.set(validator, true);
        }

        let mut message = Bytes::new(&e);
        message.append(&String::from_str(&e, "verify_identity_binding").to_xdr(&e));
        message.append(&e.current_contract_address().to_xdr(&e));
        message.append(&wallet.clone().to_xdr(&e));
        message.append(&String::from_str(&e, platform.as_str()).to_xdr(&e));
        message.append(&user_id.clone().to_xdr(&e));

        for s in signatures.iter() {
            e.crypto()
                .ed25519_verify(&s.validator, &message, &s.signature);
        }

        let platform_validated = String::from_str(&e, platform.as_str());
        write_userid_wallet_map(
            &e,
            platform_validated.clone(),
            user_id.clone(),
            wallet.clone(),
        )?;

        events::AddIdentityMapEvent {
            wallet,
            id: user_id,
            platform: platform_validated,
        }
        .publish(&e);
        Ok(())
    }

    /// Unlink identity binding by the currently bound wallet.
    ///
    /// Authorization:
    /// - The wallet currently bound to `(platform, user_id)` must authorize.
    ///
    /// Security model:
    /// - Allows a wallet owner to voluntarily remove their social identity binding.
    /// - After unlinking, rebinding must go through the normal validator-based link flow.

    fn remove_id_wallet_map(
        e: Env,
        user_id: String,
        platform_str: String,
    ) -> Result<(), RegistryError> {
        let platform = SocialPlatform::is_platform_supported(platform_str)?;
        let platform_validated = String::from_str(&e, platform.as_str());
        validate_userid(user_id.clone())?;

        let wallet = read_userid_wallet_map(&e, platform_validated.clone(), user_id.clone())?
            .ok_or(RegistryError::IdentityNotFound)?;

        wallet.require_auth();

        remove_userid_wallet_map(&e, platform_validated.clone(), user_id.clone())?;
        events::RemoveIdentityMapEvent {
            wallet,
            id: user_id,
            platform: platform_validated,
        }
        .publish(&e);

        Ok(())
    }

    /// Recovery unlink by registry manager.
    ///
    /// Authorization:
    /// - Caller must be an approved registry manager.
    ///
    /// Security model:
    /// - Used when the currently bound wallet is compromised, lost, or abandoned.
    /// - Manager can only remove the stale identity mapping.
    /// - Manager cannot rebind the identity to a new wallet.
    /// - After unlinking, the user must complete the normal identity verification flow again.
    fn manager_remove_id_wallet_map(
        e: Env,
        user_id: String,
        platform_str: String,
        manager: Address,
    ) -> Result<(), RegistryError> {
        require_registry_manager(&e, manager)?;

        let platform = SocialPlatform::is_platform_supported(platform_str)?;
        let platform_validated = String::from_str(&e, platform.as_str());

        validate_userid(user_id.clone())?;
        let wallet = read_userid_wallet_map(&e, platform_validated.clone(), user_id.clone())?
            .ok_or(RegistryError::IdentityNotFound)?;

        remove_userid_wallet_map(&e, platform_validated.clone(), user_id.clone())?;

        events::RemoveIdentityMapEvent {
            wallet,
            id: user_id,
            platform: platform_validated,
        }
        .publish(&e);

        Ok(())
    }

    // validator management

    /// Add validator.
    ///
    /// Notes:
    /// - Admin only.
    /// - Expands trusted signer set.
    fn add_validator(e: Env, validator: BytesN<32>) {
        authenticate_admin(&e);
        write_add_validator(&e, validator);
    }

    /// Remove validator.
    ///
    /// Notes:
    /// - Admin only.
    /// - Revokes validator trust for future checks.
    fn remove_validator(e: Env, validator: BytesN<32>) {
        authenticate_admin(&e);
        write_remove_validator(&e, validator)
    }

    /// Get validators.
    fn get_validators(e: Env) -> Vec<BytesN<32>> {
        read_validators(&e)
    }

    // read APIs

    /// Get wallet by `(platform, user_id)`.
    ///
    /// Notes:
    /// - Returns `None` if not found.
    fn get_wallet_by_userid(
        e: Env,
        platform: String,
        user_id: String,
    ) -> Result<Option<Address>, RegistryError> {
        read_userid_wallet_map(&e, platform, user_id)
    }

    /// Get wallet by passkey.
    ///
    /// Notes:
    /// - Returns `None` if not found.
    fn get_wallet_by_passkey(
        e: Env,
        passkey: BytesN<65>,
    ) -> Result<Option<Address>, RegistryError> {
        read_passkey_wallet_map(&e, passkey)
    }

    // admin/config

    /// Update admin.
    ///
    /// Notes:
    /// - Admin only.
    /// - Changes control over privileged registry actions.
    fn set_admin(e: Env, new_admin: Address) {
        authenticate_admin(&e);
        write_admin(&e, &new_admin);
    }

    // upgrade governance

    /// Execute approved upgrade.
    ///
    /// Notes:
    /// - Admin only.
    /// - Applies current passed proposal.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError> {
        authenticate_admin(&e);
        execute_upgrade(&e)
    }

    /// Create upgrade proposal.
    ///
    /// Notes:
    /// - Admin only.
    /// - Starts governance flow for new wasm hash.
    fn propose_upgrade(
        e: Env,
        proposal_type: String,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        create_upgrade_proposal(&e, proposal_type, &new_wasm_hash)
    }

    /// Add governance voter.
    ///
    /// Notes:
    /// - Admin only.
    fn add_voter(e: Env, voter: Address) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        upgrade_add_voter(&e, &voter)?;

        events::AddVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    /// Remove governance voter.
    ///
    /// Notes:
    /// - Admin only.
    fn remove_voter(e: Env, voter: Address) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        upgrade_remove_voter(&e, &voter)?;

        events::RemoveVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    /// Cast vote on active proposal.
    ///
    /// Notes:
    /// - Voter must authorize.
    /// - Records approval for supplied hash.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError> {
        voter.require_auth();
        write_cast_vote(&e, &voter, &wasm_hash)?;
        Ok(())
    }

    /// Cancel active proposal.
    ///
    /// Notes:
    /// - Admin only.
    fn cancel_proposal(e: Env) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        cancel_upgrade_proposal(&e)
    }
}
