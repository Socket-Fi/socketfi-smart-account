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
use crate::voters::{read_has_upgrade_passed, read_is_voter, write_add_voter, write_remove_voter};

use socketfi_shared::{constants::UPGRADE_VOTING_DURATION_SECONDS, events};
use soroban_sdk::{Address, BytesN, Env, Map, String};

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

// -----------------------------------------------------------------------------
// Upgrade Proposal Creation
// -----------------------------------------------------------------------------
// Creates a new pending upgrade proposal.
//
// FLOW:
// 1. Ensures no other proposal is currently active.
// 2. Computes and stores the voting deadline.
// 3. Stores the proposed wasm hash + proposal type.
// 4. Emits proposal event.
//
// NOTE:
// - `proposal_type` determines execution behavior later.
// - Voting window length is controlled by UPGRADE_VOTING_DURATION_SECONDS.
//
// SECURITY:
// - This helper assumes caller already enforced proposer authorization.
// - Only one active proposal can exist at a time.
pub fn create_upgrade_proposal(
    e: &Env,
    proposal_type: String,
    wasm_hash: &BytesN<32>,
) -> Result<(), UpgradeError> {
    if get_upgrade_voting_deadline(e) != 0 {
        return Err(UpgradeError::AnotherUpgradePending);
    }

    let deadline = e.ledger().timestamp() + UPGRADE_VOTING_DURATION_SECONDS;
    write_upgrade_voting_deadline(e, &deadline);
    write_future_wasm(e, proposal_type, wasm_hash)?;

    events::UpgradeProposalEvent {
        wasm: wasm_hash.clone(),
        voting_deadline: deadline,
    }
    .publish(&e);

    Ok(())
}

// -----------------------------------------------------------------------------
// Voting
// -----------------------------------------------------------------------------
// Casts a vote for the currently active proposal.
//
// REQUIREMENTS:
// - A proposal must exist.
// - Voting must still be open.
// - Voter must be on the approved voter list.
// - Voter may only vote once.
// - Provided wasm hash must match the active proposal.
//
// NOTE:
// - This function records the vote in persistent storage.
// - Vote uniqueness is enforced through the VotedList map.
//
// IMPORTANT:
// - `read_future_wasm(e).unwrap()` assumes proposal state is internally consistent
//   once a non-zero voting deadline exists.
// - If state corruption is possible elsewhere, that unwrap would become fragile.
//
// SECURITY:
// - This helper checks voter eligibility.
// - If caller also expects signature/auth, that should be enforced outside or
//   before this helper is invoked.
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

    if !read_is_voter(e, voter.clone()) {
        return Err(UpgradeError::NotInVotersList);
    }

    let future_wasm_hash = read_future_wasm(e).unwrap();
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

// -----------------------------------------------------------------------------
// Proposal Execution
// -----------------------------------------------------------------------------
// Finalizes the active proposal after the voting deadline has passed.
//
// BEHAVIOR BY PROPOSAL TYPE:
// - Upgrade:
//     clears pending state, then upgrades current contract WASM.
// - WalletVersion:
//     writes approved wallet version hash, then clears pending state.
//
// REQUIREMENTS:
// - Proposal must exist.
// - Voting period must be over.
// - Proposal must meet passing threshold.
//
// IMPORTANT ORDERING:
// - For `Upgrade`, pending state is cleared before `update_current_contract_wasm`
//   so stale proposal state is not left behind if the WASM update succeeds.
// - For `WalletVersion`, the version write happens before clearing proposal
//   state because the write may fail and should not silently discard proposal state.
//
// NOTE:
// - `read_future_wasm(...).unwrap()` and `read_proposal_type(...).unwrap()` assume
//   proposal state is valid whenever a deadline is present.
pub fn execute_upgrade(e: &Env) -> Result<BytesN<32>, UpgradeError> {
    let deadline = get_upgrade_voting_deadline(e);

    if deadline == 0 {
        return Err(UpgradeError::NoPendingUpgradeAction);
    }

    if e.ledger().timestamp() < deadline {
        return Err(UpgradeError::VotingStillOngoing);
    }

    let new_wasm_hash = read_future_wasm(e).unwrap();
    let proposal_type: UpgradeType = read_proposal_type(e).unwrap();
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

// -----------------------------------------------------------------------------
// Proposal Cancellation
// -----------------------------------------------------------------------------
// Cancels the active proposal and clears all pending proposal state.
//
// NOTE:
// - Intended for authorized administrative/governance cancellation flow.
// - Emits cancellation event using the currently pending wasm hash.
//
// IMPORTANT:
// - `read_future_wasm(e).unwrap()` assumes a valid pending proposal exists when
//   this helper is called.
// - This function does not itself verify that a proposal exists before unwrap.
//
// SECURITY:
// - Caller should enforce authorization before invoking this helper.
pub fn cancel_upgrade_proposal(e: &Env) -> Result<(), UpgradeError> {
    let wasm = read_future_wasm(e).unwrap();
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

// -----------------------------------------------------------------------------
// Voter Management
// -----------------------------------------------------------------------------
// Adds a new voter to the approved voter set.
//
// NOTE:
// - This helper does not enforce authorization by itself.
// - Intended to be called only from protected admin/governance entrypoints.
pub fn upgrade_add_voter(e: &Env, voter: &Address) {
    write_add_voter(e, voter);
}

// Removes a voter from the approved voter set.
//
// NOTE:
// - This helper does not enforce authorization by itself.
// - Intended to be called only from protected admin/governance entrypoints.
pub fn upgrade_remove_voter(e: &Env, voter: &Address) {
    write_remove_voter(e, voter);
}
