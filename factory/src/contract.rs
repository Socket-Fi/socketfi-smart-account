use crate::{
    contract_trait::FactoryTrait,
    wallet_factory::{
        read_creation_pop_challenge, write_create_wallet, write_creation_nonce_used,
        write_rpid_hash,
    },
};
use socketfi_access::access::{
    authenticate_admin, has_admin, read_admin, read_fee_manager, read_registry, write_admin,
    write_fee_manager, write_registry, write_social_router,
};
use socketfi_shared::events;
use socketfi_webauthn::{
    key_types::{extract_bls_keys, BlsKeyWithPoP, PasskeySignature},
    wallet_error::WalletError,
};
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Symbol, Vec};
use upgrade::{
    cancel_upgrade_proposal, create_upgrade_proposal, errors::UpgradeError, execute_upgrade,
    init_wallet_wasm_hash, read_wallet_wasm_hash, upgrade_add_voter, upgrade_remove_voter,
    write_cast_vote,
};

/// Factory contract for wallet deployment and wallet-version governance.
///
/// Notes:
/// - Stores shared dependencies used when deploying new wallets.
/// - Exposes admin-controlled configuration updates.
/// - Exposes governance actions for wallet version / upgrade flow.
#[contract]
pub struct FactoryContract;

#[contractimpl]
impl FactoryTrait for FactoryContract {
    // initialization

    /// Initialize the factory and its core dependencies.
    ///
    /// Auth:
    /// - Intended to run once during contract setup.
    ///
    /// Effects:
    /// - Stores admin and dependency contract addresses.
    /// - Stores the initial approved wallet wasm hash.
    /// - Adds the initial admin as a governance voter.
    ///
    /// Notes:
    /// - Re-initialization is blocked once admin state exists.
    /// - New wallets deployed after this point inherit the configured dependencies.
    fn __constructor(
        e: Env,
        admin: Address,
        registry: Address,
        social_router: Address,
        fee_manager: Address,
        rpid: String,
        wasm: BytesN<32>,
    ) -> Result<(), UpgradeError> {
        if has_admin(&e) {
            return Err(UpgradeError::AlreadyInitialized);
        }

        write_admin(&e, &admin);
        write_registry(&e, &registry);
        write_social_router(&e, &social_router);
        write_fee_manager(&e, &fee_manager);
        write_rpid_hash(&e, &rpid);

        // Store the initial wallet version approved for deployment.
        init_wallet_wasm_hash(&e, &wasm)?;

        // Bootstrap governance by allowing the initial admin to vote.
        upgrade_add_voter(&e, &admin)?;

        Ok(())
    }

    // wallet creation

    /// Deploy and initialize a new wallet instance.
    ///
    /// Verifies:
    /// - passkey proof over the wallet-creation challenge
    /// - each BLS public key proof over the same challenge
    /// - nonce freshness through the creation challenge flow
    ///
    /// Effects:
    /// - deploys wallet using the current approved wallet wasm hash
    /// - stores the nonce as used
    /// - emits wallet creation event
    fn create_wallet(
        e: Env,
        passkey: BytesN<65>,
        passkey_sig: PasskeySignature,
        bls_keys_pop: Vec<BlsKeyWithPoP>,
        nonce: BytesN<32>,
        network: Symbol,
    ) -> Result<Address, WalletError> {
        let challenge = read_creation_pop_challenge(&e, &nonce, &network)?;
        let wallet_address =
            write_create_wallet(&e, &passkey, passkey_sig, bls_keys_pop.clone(), challenge)?;
        // write_create_wallet(&e, &passkey_pop.key, bls_keys.clone(), challenge)?;

        write_creation_nonce_used(&e, &nonce);

        events::WalletCreationEvent {
            wallet: wallet_address.clone(),
            passkey,
            bls_keys: extract_bls_keys(&e, bls_keys_pop),
        }
        .publish(&e);

        Ok(wallet_address)
    }

    // read-only getters

    /// Return the currently approved wallet version hash.
    ///
    /// Notes:
    /// - Read-only helper used to inspect deployment version state.
    fn get_wallet_wasm_hash(e: Env) -> Option<BytesN<32>> {
        read_wallet_wasm_hash(&e)
    }

    /// Returns the deterministic wallet-creation proof challenge.
    ///
    /// The challenge is derived from the configured RP ID hash, network, and nonce.
    /// It is used off-chain by the passkey and BLS signers so all parties sign the
    /// same wallet-creation intent.
    fn get_pop_challenge(
        e: Env,
        nonce: BytesN<32>,
        network: Symbol,
    ) -> Result<BytesN<32>, WalletError> {
        read_creation_pop_challenge(&e, &nonce, &network)
    }

    /// Return the current admin address.
    ///
    /// Notes:
    /// - Read-only helper for configuration inspection.
    fn get_admin(e: Env) -> Option<Address> {
        read_admin(&e)
    }

    /// Return the configured registry contract address.
    ///
    /// Notes:
    /// - Read-only helper for dependency inspection.
    fn get_registry(e: Env) -> Option<Address> {
        read_registry(&e)
    }

    /// Return the configured fee manager contract address.
    ///
    /// Notes:
    /// - Read-only helper for dependency inspection.
    fn get_fee_manager(e: Env) -> Option<Address> {
        read_fee_manager(&e)
    }

    // admin configuration updates

    /// Update the factory admin address.
    ///
    /// Auth:
    /// - Current admin authorization required.
    ///
    /// Effects:
    /// - Replaces the account that controls privileged factory actions.
    /// - Emits an admin update event.
    fn update_admin(e: Env, new_admin: Address) {
        authenticate_admin(&e);
        write_admin(&e, &new_admin);

        events::UpdateAdminEvent {
            value: new_admin.clone(),
        }
        .publish(&e);
    }

    /// Update the registry dependency used by the factory.
    ///
    /// Auth:
    /// - Admin only.
    ///
    /// Effects:
    /// - Replaces the registry address used for future wallet deployments.
    /// - Emits a registry update event.
    fn update_registry(e: Env, registry: Address) {
        authenticate_admin(&e);
        write_registry(&e, &registry);

        events::UpdateRegistryEvent {
            value: registry.clone(),
        }
        .publish(&e);
    }

    /// Update the social router dependency used by the factory.
    ///
    /// Auth:
    /// - Admin only.
    ///
    /// Effects:
    /// - Replaces the social router address used for future wallet deployments.
    /// - Emits a social router update event.
    fn update_social_router(e: Env, social_router: Address) {
        authenticate_admin(&e);
        write_social_router(&e, &social_router);

        events::UpdateSocialRouterEvent {
            value: social_router.clone(),
        }
        .publish(&e);
    }

    /// Update the fee manager dependency used by the factory.
    ///
    /// Auth:
    /// - Admin only.
    ///
    /// Effects:
    /// - Replaces the fee manager address used for future wallet deployments.
    /// - Emits a fee manager update event.
    fn update_fee_manager(e: Env, fee_manager: Address) {
        authenticate_admin(&e);
        write_fee_manager(&e, &fee_manager);

        events::UpdateFeeManagerEvent {
            value: fee_manager.clone(),
        }
        .publish(&e);
    }

    // upgrade governance

    /// Execute a passed upgrade proposal.
    ///
    /// Auth:
    /// - Admin authorization required to trigger execution.
    ///
    /// Effects:
    /// - Applies the approved governance outcome.
    /// - Returns the wasm hash that was applied or activated.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError> {
        authenticate_admin(&e);
        execute_upgrade(&e)
    }

    /// Create a new upgrade proposal.
    ///
    /// Auth:
    /// - Admin only.
    ///
    /// Effects:
    /// - Starts a new proposal for upgrade governance.
    /// - Stores the proposed target hash for voting/execution flow.
    fn propose_upgrade(
        e: Env,
        proposal_type: String,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        create_upgrade_proposal(&e, proposal_type, &new_wasm_hash)?;
        Ok(())
    }

    fn add_voter(e: Env, voter: Address) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        upgrade_add_voter(&e, &voter)?;

        events::AddVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    fn remove_voter(e: Env, voter: Address) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        upgrade_remove_voter(&e, &voter)?;

        events::RemoveVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    /// Cast a vote for the currently active proposal.
    ///
    /// Auth:
    /// - The provided voter address must authorize the call.
    ///
    /// Effects:
    /// - Records the voter’s approval for the supplied proposal hash.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError> {
        voter.require_auth();
        write_cast_vote(&e, &voter, &wasm_hash)?;
        Ok(())
    }

    /// Cancel the currently active proposal.
    ///
    /// Auth:
    /// - Admin only.
    ///
    /// Effects:
    /// - Clears the active proposal state before execution.
    fn cancel_proposal(e: Env) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        cancel_upgrade_proposal(&e)?;
        Ok(())
    }
}
