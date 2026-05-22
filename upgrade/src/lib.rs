#![no_std]

pub mod errors;
mod storage;
mod types;
pub mod voters;

use crate::errors::UpgradeError;
use crate::storage::{
    clear_pending_upgrade_state, get_upgrade_voting_deadline, read_future_wasm, read_proposal_type,
    read_wallet_wasm_version, write_future_wasm, write_upgrade_voting_deadline,
    write_wallet_wasm_version, DataKey,
};
use crate::types::UpgradeType;
use crate::voters::{read_has_upgrade_passed, write_add_voter, write_remove_voter};

use socketfi_shared::{constants::UPGRADE_VOTING_DURATION_SECONDS, events};
use soroban_sdk::{Address, BytesN, Env, Map, String};
use storage::{has_active_upgrade_proposal, write_proposal_snapshot};
use voters::get_voter_info;

// -----------------------------------------------------------------------------
// Wallet Version Initialization
// -----------------------------------------------------------------------------
// NOTE:
// - Intended to be called once during initial contract setup.
// - Prevents overwriting an already established wallet version hash.
// - Uses persistent storage because wallet version must survive contract upgrades.
//
// SECURITY:
// - This helper does not perform auth itself.
// - It should only be called from a protected initialization path.
//
// ERROR:
// - AlreadyInitialized -> if wallet version has already been set.
pub fn init_wallet_wasm_hash(e: &Env, wallet_version: &BytesN<32>) -> Result<(), UpgradeError> {
    if e.storage()
        .persistent()
        .get::<_, BytesN<32>>(&DataKey::WalletVersion)
        .is_some()
    {
        return Err(UpgradeError::AlreadyInitialized);
    }

    write_wallet_wasm_version(e, wallet_version);
    Ok(())
}

// Creates a new upgrade proposal and snapshots governance state.
//
// SECURITY:
// - Only one active proposal may exist at a time.
// - Expired pending proposal state is cleared before creating a new proposal.
// - The approval threshold and eligible voter set are snapshotted at creation.
// - Later voter additions/removals only affect future proposals.
pub fn create_upgrade_proposal(
    e: &Env,
    proposal_type: String,
    wasm_hash: &BytesN<32>,
) -> Result<(), UpgradeError> {
    if has_active_upgrade_proposal(e) {
        return Err(UpgradeError::AnotherUpgradePending);
    }

    if get_upgrade_voting_deadline(e) != 0 {
        clear_pending_upgrade_state(e);
    }

    let (_, approval_threshold, voters) = get_voter_info(e)?;

    let deadline = e.ledger().timestamp() + UPGRADE_VOTING_DURATION_SECONDS;

    write_proposal_snapshot(e, approval_threshold, &voters);
    write_upgrade_voting_deadline(e, &deadline);
    write_future_wasm(e, proposal_type, wasm_hash)?;

    events::UpgradeProposalEvent {
        wasm: wasm_hash.clone(),
        voting_deadline: deadline,
    }
    .publish(&e);

    Ok(())
}

// Casts a vote for the active proposal.
//
// SECURITY:
// - Voting is only allowed before the proposal deadline.
// - Voter eligibility is checked against the proposal voter snapshot,
//   not the current mutable voter list.
// - This prevents voter additions/removals from affecting active proposals.
// - Each snapshot voter may vote only once.
// - The submitted wasm hash must match the active proposal hash.
pub fn write_cast_vote(
    e: &Env,
    voter: &Address,
    wasm_hash: &BytesN<32>,
) -> Result<(), UpgradeError> {
    let deadline = get_upgrade_voting_deadline(e);

    if deadline == 0 {
        return Err(UpgradeError::NoPendingUpgradeAction);
    }

    if e.ledger().timestamp() > deadline {
        return Err(UpgradeError::VotingClosed);
    }

    let proposal_voters = crate::storage::read_proposal_voters(e)?;

    if !proposal_voters.contains_key(voter.clone()) {
        return Err(UpgradeError::NotInVotersList);
    }

    let future_wasm_hash = read_future_wasm(e).ok_or(UpgradeError::NoPendingUpgradeAction)?;
    if future_wasm_hash != *wasm_hash {
        return Err(UpgradeError::InvalidUpgradeHash);
    }

    let key = DataKey::VotedList;
    let mut voted: Map<Address, ()> = e.storage().persistent().get(&key).unwrap_or(Map::new(e));

    if voted.contains_key(voter.clone()) {
        return Err(UpgradeError::AlreadyVoted);
    }

    voted.set(voter.clone(), ());
    e.storage().persistent().set(&key, &voted);

    events::VoteEvent {
        wasm: wasm_hash.clone(),
        voter: voter.clone(),
    }
    .publish(&e);

    Ok(())
}

// Executes a passed proposal after the voting deadline.
//
// SECURITY:
// - Uses the snapshotted approval threshold and voter set.
// - Clears proposal state after successful execution.
// - Proposal data is read with checked errors instead of unwraps.
pub fn execute_upgrade(e: &Env) -> Result<BytesN<32>, UpgradeError> {
    let deadline = get_upgrade_voting_deadline(e);

    if deadline == 0 {
        return Err(UpgradeError::NoPendingUpgradeAction);
    }

    if e.ledger().timestamp() < deadline {
        return Err(UpgradeError::VotingStillOngoing);
    }

    let new_wasm_hash = read_future_wasm(e).ok_or(UpgradeError::NoPendingUpgradeAction)?;
    let proposal_type: UpgradeType =
        read_proposal_type(e).ok_or(UpgradeError::NoPendingUpgradeAction)?;
    let (_, has_passed) = read_has_upgrade_passed(e)?;

    if !has_passed {
        return Err(UpgradeError::DidNotPass);
    }

    match proposal_type {
        UpgradeType::Upgrade => {
            clear_pending_upgrade_state(e);
            e.deployer()
                .update_current_contract_wasm(new_wasm_hash.clone());

            events::ContractUpgradeEvent {
                wasm: new_wasm_hash.clone(),
            }
            .publish(&e);
        }
        UpgradeType::WalletVersion => {
            write_wallet_wasm_version(e, &new_wasm_hash);
            clear_pending_upgrade_state(e);

            events::WalletVersionUpgradeEvent {
                wasm: new_wasm_hash.clone(),
            }
            .publish(&e);
        }
    }

    Ok(new_wasm_hash)
}

// Cancels the pending proposal and clears all proposal state.
//
// SECURITY:
// - Caller must enforce authorization before invoking this helper.
// - Returns NoPendingUpgradeAction if no proposal wasm hash exists.
// - Clears votes, deadline, proposal type, threshold, and voter snapshot.
pub fn cancel_upgrade_proposal(e: &Env) -> Result<(), UpgradeError> {
    let wasm = read_future_wasm(e).ok_or(UpgradeError::NoPendingUpgradeAction)?;
    clear_pending_upgrade_state(e);

    events::UpgradeCancelledEvent { wasm: wasm.clone() }.publish(&e);
    Ok(())
}

// -----------------------------------------------------------------------------
// Read Helpers
// -----------------------------------------------------------------------------
// Returns `(vote_count, has_passed)` for the current active proposal.
//
// NOTE:
// - Delegates threshold logic to voters module.
pub fn get_upgrade_votes(e: &Env) -> Result<(u32, bool), UpgradeError> {
    read_has_upgrade_passed(e)
}

// Returns the currently approved wallet version hash, if set.
//
// NOTE:
// - Returns None if wallet version has not been initialized yet.
pub fn read_wallet_wasm_hash(e: &Env) -> Option<BytesN<32>> {
    read_wallet_wasm_version(e)
}

// Updates the current governance voter set.
//
// SECURITY:
// - Blocked while an upgrade proposal is active.
// - Changes only affect future proposals because active proposals use
//   their snapshotted voter set and threshold..
pub fn upgrade_add_voter(e: &Env, voter: &Address) -> Result<(), UpgradeError> {
    if has_active_upgrade_proposal(e) {
        return Err(UpgradeError::AnotherUpgradePending);
    }

    write_add_voter(e, voter);
    Ok(())
}

// Updates the current governance voter set.
//
// SECURITY:
// - Blocked while an upgrade proposal is active.
// - Changes only affect future proposals because active proposals use
//   their snapshotted voter set and threshold.
pub fn upgrade_remove_voter(e: &Env, voter: &Address) -> Result<(), UpgradeError> {
    if has_active_upgrade_proposal(e) {
        return Err(UpgradeError::AnotherUpgradePending);
    }

    write_remove_voter(e, voter);
    Ok(())
}
