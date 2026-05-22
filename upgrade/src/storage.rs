use crate::errors::UpgradeError;
use crate::types::UpgradeType;
use soroban_sdk::{contracttype, Address, BytesN, Env, Map, String};

#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    UpgradeVotingDeadline,
    FutureWASM,
    VotersList,
    VotedList,
    WalletVersion,
    ProposalType,

    // Snapshot state
    ProposalApprovalThreshold,
    ProposalVoters,
}

pub fn has_active_upgrade_proposal(e: &Env) -> bool {
    let deadline = get_upgrade_voting_deadline(e);

    deadline != 0 && e.ledger().timestamp() <= deadline
}

pub fn get_upgrade_voting_deadline(e: &Env) -> u64 {
    e.storage()
        .instance()
        .get(&DataKey::UpgradeVotingDeadline)
        .unwrap_or(0)
}

pub fn write_upgrade_voting_deadline(e: &Env, value: &u64) {
    e.storage()
        .instance()
        .set(&DataKey::UpgradeVotingDeadline, value);
}

pub fn read_future_wasm(e: &Env) -> Option<BytesN<32>> {
    e.storage().instance().get(&DataKey::FutureWASM)
}

pub fn read_proposal_type(e: &Env) -> Option<UpgradeType> {
    e.storage().instance().get(&DataKey::ProposalType)
}

pub fn write_future_wasm(
    e: &Env,
    proposal_type: String,
    wasm: &BytesN<32>,
) -> Result<(), UpgradeError> {
    let proposal_type =
        UpgradeType::upgrade_type(proposal_type).ok_or(UpgradeError::UpgradeTypeNotFound)?;

    e.storage().instance().set(&DataKey::FutureWASM, wasm);
    e.storage()
        .instance()
        .set(&DataKey::ProposalType, &proposal_type);

    Ok(())
}

pub fn write_wallet_wasm_version(e: &Env, wasm_hash: &BytesN<32>) {
    e.storage()
        .instance()
        .set(&DataKey::WalletVersion, wasm_hash);
}

pub fn read_wallet_wasm_version(e: &Env) -> Option<BytesN<32>> {
    e.storage().instance().get(&DataKey::WalletVersion)
}

// -----------------------------------------------------------------------------
// Proposal Snapshot
// -----------------------------------------------------------------------------

pub fn write_proposal_snapshot(e: &Env, approval_threshold: u32, voters: &Map<Address, ()>) {
    e.storage()
        .instance()
        .set(&DataKey::ProposalApprovalThreshold, &approval_threshold);

    e.storage()
        .persistent()
        .set(&DataKey::ProposalVoters, voters);
}

pub fn read_proposal_approval_threshold(e: &Env) -> Result<u32, UpgradeError> {
    e.storage()
        .instance()
        .get(&DataKey::ProposalApprovalThreshold)
        .ok_or(UpgradeError::NoPendingUpgradeAction)
}

pub fn read_proposal_voters(e: &Env) -> Result<Map<Address, ()>, UpgradeError> {
    e.storage()
        .persistent()
        .get(&DataKey::ProposalVoters)
        .ok_or(UpgradeError::NoPendingUpgradeAction)
}

pub fn clear_pending_upgrade_state(e: &Env) {
    e.storage()
        .instance()
        .remove(&DataKey::UpgradeVotingDeadline);

    e.storage().instance().remove(&DataKey::FutureWASM);

    e.storage().instance().remove(&DataKey::ProposalType);

    e.storage()
        .instance()
        .remove(&DataKey::ProposalApprovalThreshold);

    e.storage().persistent().remove(&DataKey::VotedList);

    e.storage().persistent().remove(&DataKey::ProposalVoters);
}
