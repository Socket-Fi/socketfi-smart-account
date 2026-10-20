use crate::{
    account_factory::{
        is_registered_account as read_registered_account, read_creation_pop_challenge,
        read_expected_network, write_create_account, write_creation_nonce_used,
        write_expected_network, write_registered_account, write_rpid_hash,
    },
    contract_trait::FactoryTrait,
};
use socketfi_access::access::{authenticate_admin, has_admin, read_admin, write_admin};
use socketfi_shared::{
    account_error::AccountError,
    events,
    key_types::{extract_bls_keys, BlsKeyWithPoP, EvmSignature, PasskeySignature},
};

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env, String, Symbol, Vec};
use upgrade::{
    authorize_governance_action, cancel_upgrade_proposal, create_upgrade_proposal,
    errors::UpgradeError, execute_upgrade, init_account_wasm_hash, init_factory_wasm_hash,
    init_governance_voters, read_account_wasm_hash, upgrade_add_voter, upgrade_remove_voter,
    write_cast_vote,
};

/// Factory contract for account deployment and account-version governance.
#[contract]
pub struct FactoryContract;

#[contractimpl]
impl FactoryTrait for FactoryContract {
    /// Initializes the factory with admin, RP ID, and initial account WASM hash.
    fn __constructor(
        e: Env,
        admin: Address,
        rpid: String,
        network: Symbol,
        factory_wasm: BytesN<32>,
        account_wasm: BytesN<32>,
        voters: Vec<Address>,
    ) -> Result<(), UpgradeError> {
        if has_admin(&e) {
            return Err(UpgradeError::AlreadyInitialized);
        }
        let mut admin_is_voter = false;
        for voter in voters.iter() {
            if voter == admin {
                admin_is_voter = true;
            }
        }
        if !admin_is_voter {
            return Err(UpgradeError::AdminMustBeVoter);
        }

        write_admin(&e, &admin);
        write_rpid_hash(&e, &rpid);
        write_expected_network(&e, &network).map_err(|_| UpgradeError::InvalidNetwork)?;
        init_account_wasm_hash(&e, &account_wasm)?;
        init_factory_wasm_hash(&e, &factory_wasm);
        init_governance_voters(&e, &voters)?;

        Ok(())
    }

    /// Deploys and initializes a new account after verifying creation proofs.
    fn create_account(
        e: Env,
        passkey: Option<BytesN<65>>,
        passkey_sig: Option<PasskeySignature>,
        stellar_signer: Option<BytesN<32>>,
        stellar_address: Option<Address>,
        evm_signer: Option<BytesN<20>>,
        evm_sig: Option<EvmSignature>,

        bls_keys_pop: Vec<BlsKeyWithPoP>,
        nonce: BytesN<32>,
        network: Symbol,
        guardians: Vec<Address>,
        live_until_ledger: u32,
    ) -> Result<Address, AccountError> {
        let bls_keys = extract_bls_keys(&e, bls_keys_pop.clone());
        let challenge = read_creation_pop_challenge(
            &e,
            passkey.clone(),
            stellar_signer.clone(),
            evm_signer.clone(),
            bls_keys.clone(),
            &nonce,
            &network,
            guardians.clone(),
            live_until_ledger,
        )?;

        let account_address = write_create_account(
            &e,
            challenge,
            passkey.clone(),
            passkey_sig,
            stellar_signer.clone(),
            stellar_address,
            evm_signer.clone(),
            evm_sig,
            bls_keys_pop.clone(),
            guardians,
        )?;

        write_creation_nonce_used(&e, &nonce, live_until_ledger)?;
        write_registered_account(&e, &account_address);
        let account_wasm =
            read_account_wasm_hash(&e).ok_or(AccountError::AccountVersionNotFound)?;

        events::AccountCreationEvent {
            account: account_address.clone(),
            passkey,
            stellar_signer,
            evm_signer,
            bls_keys,
        }
        .publish(&e);
        events::AccountRegisteredEvent {
            account: account_address.clone(),
            network,
            nonce,
            wasm: account_wasm,
        }
        .publish(&e);

        Ok(account_address)
    }

    /// Updates the factory admin.
    fn update_admin(
        e: Env,
        new_admin: Address,
        approvals: Vec<Address>,
    ) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        authorize_governance_action(&e, &approvals)?;
        if !upgrade::voters::is_voter(&e, &new_admin) {
            return Err(UpgradeError::AdminMustBeVoter);
        }
        write_admin(&e, &new_admin);

        events::UpdateAdminEvent {
            value: new_admin.clone(),
        }
        .publish(&e);
        Ok(())
    }

    /// Creates a account upgrade proposal.
    fn propose_upgrade(
        e: Env,
        proposal_type: String,
        new_wasm_hash: BytesN<32>,
    ) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        create_upgrade_proposal(&e, proposal_type, &new_wasm_hash)?;
        Ok(())
    }

    /// Casts a vote for an active account upgrade proposal.
    fn cast_vote(e: Env, voter: Address, wasm_hash: BytesN<32>) -> Result<(), UpgradeError> {
        voter.require_auth();
        write_cast_vote(&e, &voter, &wasm_hash)?;
        Ok(())
    }

    /// Executes an approved account upgrade proposal.
    fn apply_upgrade(e: Env) -> Result<BytesN<32>, UpgradeError> {
        execute_upgrade(&e)
    }

    /// Cancels the active account upgrade proposal.
    fn cancel_proposal(e: Env, approvals: Vec<Address>) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        authorize_governance_action(&e, &approvals)?;
        cancel_upgrade_proposal(&e)?;
        Ok(())
    }

    /// Adds a governance voter.
    fn add_voter(e: Env, voter: Address, approvals: Vec<Address>) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        upgrade_add_voter(&e, &voter, &approvals)?;

        events::AddVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    /// Removes a governance voter.
    fn remove_voter(e: Env, voter: Address, approvals: Vec<Address>) -> Result<(), UpgradeError> {
        authenticate_admin(&e);
        if read_admin(&e) == Some(voter.clone()) {
            return Err(UpgradeError::AdminMustBeVoter);
        }
        upgrade_remove_voter(&e, &voter, &approvals)?;

        events::RemoveVoterEvent {
            value: voter.clone(),
        }
        .publish(&e);

        Ok(())
    }

    /// Returns the currently approved account WASM hash.
    fn get_latest_account_wasm(e: Env) -> Result<BytesN<32>, UpgradeError> {
        read_account_wasm_hash(&e).ok_or(UpgradeError::NotFound)
    }

    /// Returns the deterministic account creation proof challenge.
    fn get_pop_challenge(
        e: Env,
        passkey: Option<BytesN<65>>,
        stellar_signer: Option<BytesN<32>>,
        evm_signer: Option<BytesN<20>>,
        bls_keys: Vec<BytesN<96>>,
        nonce: BytesN<32>,
        network: Symbol,
        guardians: Vec<Address>,
        live_until_ledger: u32,
    ) -> Result<BytesN<32>, AccountError> {
        read_creation_pop_challenge(
            &e,
            passkey,
            stellar_signer,
            evm_signer,
            bls_keys,
            &nonce,
            &network,
            guardians,
            live_until_ledger,
        )
    }

    fn is_registered_account(e: Env, account: Address) -> bool {
        read_registered_account(&e, &account)
    }

    fn get_network(e: Env) -> Option<Symbol> {
        read_expected_network(&e)
    }

    /// Returns the current factory admin.
    fn get_admin(e: Env) -> Option<Address> {
        read_admin(&e)
    }
}
