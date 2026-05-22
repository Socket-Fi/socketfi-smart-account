use soroban_sdk::{
    contract, contractimpl, xdr::ToXdr, Address, Bytes, BytesN, Env, Map, String, Vec,
};

use crate::{
    contract_trait::RegistryTrait,
    registry::{
        read_passkey_wallet_map, read_userid_wallet_map, write_passkey_wallet_map,
        write_userid_wallet_map,
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

    // identity core

    /// Verify identity and bind wallet.
    ///
    /// Notes:
    /// - Requires wallet authorization.
    /// - Validates platform, user id, and validator signatures.
    /// - Writes `(platform, user_id) -> wallet` mapping on success.
    fn verify_identity_binding(
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

        write_userid_wallet_map(&e, String::from_str(&e, platform.as_str()), user_id, wallet)?;

        Ok(())
    }

    /// Set passkey -> wallet mapping.
    ///
    /// Notes:
    /// - Factory only.
    /// - Used for wallet lookup by passkey.
    fn set_passkey_wallet_map(
        e: Env,
        passkey: BytesN<77>,
        wallet: Address,
    ) -> Result<(), RegistryError> {
        read_factory(&e).unwrap().require_auth();
        write_passkey_wallet_map(&e, passkey, wallet)
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
        passkey: BytesN<77>,
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
