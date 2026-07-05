use crate::{
    contract_trait::FactoryTrait,
    wallet_factory::{
        read_creation_pop_challenge, write_create_wallet, write_creation_nonce_used,
        write_rpid_hash,
    },
};
use socketfi_access::access::{authenticate_admin, has_admin, read_admin, write_admin};
use socketfi_shared::{
    events,
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
#[contract]
pub struct FactoryContract;

#[contractimpl]
impl FactoryTrait for FactoryContract {
    /// Initializes the factory with admin, RP ID, and initial wallet WASM hash.
    fn __constructor(
        e: Env,
        admin: Address,
        rpid: String,
        wasm: BytesN<32>,
    ) -> Result<(), UpgradeError> {
        if has_admin(&e) {
            return Err(UpgradeError::AlreadyInitialized);
        }

        write_admin(&e, &admin);
        write_rpid_hash(&e, &rpid);
        init_wallet_wasm_hash(&e, &wasm)?;
        upgrade_add_voter(&e, &admin)?;

        Ok(())
    }

    /// Deploys and initializes a new wallet after verifying creation proofs.
    fn create_wallet(
        e: Env,
        passkey: BytesN<65>,
        passkey_sig: PasskeySignature,
        bls_keys_pop: Vec<BlsKeyWithPoP>,
        nonce: BytesN<32>,
        network: Symbol,
        guardians: Vec<Address>,
    ) -> Result<Address, WalletError> {
        let challenge = read_creation_pop_challenge(&e, &nonce, &network)?;
        let wallet_address = write_create_wallet(
            &e,
            &passkey,
            passkey_sig,
            bls_keys_pop.clone(),
            challenge,
            guardians,
        )?;

        write_creation_nonce_used(&e, &nonce);

        events::WalletCreationEvent {
            wallet: wallet_address.clone(),
            passkey,
            bls_keys: extract_bls_keys(&e, bls_keys_pop),
        }
        .publish(&e);

        Ok(wallet_address)
    }

    /// Updates the factory admin.
    fn update_admin(e: Env, new_admin: Address) {
        authenticate_admin(&e);
        write_admin(&e, &new_admin);

        events::UpdateAdminEvent {
            value: new_admin.clone(),
        }
        .publish(&e);
    }

    /// Creates a wallet upgrade proposal.
    fn propose_upgrade(
        e: Env,
        proposal_type: String,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        create_upgrade_proposal(&e, proposal_type, &new_wasm_hash)?;
        Ok(())
    }

    /// Casts a vote for an active wallet upgrade proposal.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError> {
        voter.require_auth();
        write_cast_vote(&e, &voter, &wasm_hash)?;
        Ok(())
    }

    /// Executes an approved wallet upgrade proposal.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError> {
        authenticate_admin(&e);
        execute_upgrade(&e)
    }

    /// Cancels the active wallet upgrade proposal.
    fn cancel_proposal(e: Env) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        cancel_upgrade_proposal(&e)?;
        Ok(())
    }

    /// Adds a governance voter.
    fn add_voter(e: Env, voter: Address) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        upgrade_add_voter(&e, &voter)?;

        events::AddVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    /// Removes a governance voter.
    fn remove_voter(e: Env, voter: Address) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        upgrade_remove_voter(&e, &voter)?;

        events::RemoveVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    /// Returns the currently approved wallet WASM hash.
    fn get_wallet_wasm_hash(e: Env) -> Option<BytesN<32>> {
        read_wallet_wasm_hash(&e)
    }

    /// Returns the deterministic wallet creation proof challenge.
    fn get_pop_challenge(
        e: Env,
        nonce: BytesN<32>,
        network: Symbol,
    ) -> Result<BytesN<32>, WalletError> {
        read_creation_pop_challenge(&e, &nonce, &network)
    }

    /// Returns the current factory admin.
    fn get_admin(e: Env) -> Option<Address> {
        read_admin(&e)
    }
}
