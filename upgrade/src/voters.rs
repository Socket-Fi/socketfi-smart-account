use crate::errors::UpgradeError;
use crate::storage::{read_proposal_approval_threshold, read_proposal_voters, DataKey};
use socketfi_shared::constants::{MIN_GOVERNANCE_VOTERS, VOTING_THRESHOLD};
use socketfi_shared::ttl::bump_persistent;
use soroban_sdk::{Address, Env, Map};

pub fn read_voters(e: &Env) -> Map<Address, ()> {
    let key = DataKey::VotersList;

    if let Some(voters) = e.storage().persistent().get(&key) {
        bump_persistent(e, &key);
        voters
    } else {
        Map::new(e)
    }
}

pub fn is_voter(e: &Env, voter: &Address) -> bool {
    read_voters(e).contains_key(voter.clone())
}

pub fn write_voters(e: &Env, voters: &Map<Address, ()>) {
    let key = DataKey::VotersList;
    e.storage().persistent().set(&key, voters);
    bump_persistent(e, &key);
}

pub fn write_add_voter(e: &Env, voter: &Address) -> Result<(), UpgradeError> {
    let mut voters = read_voters(e);
    if voters.contains_key(voter.clone()) {
        return Err(UpgradeError::DuplicateVoter);
    }
    voters.set(voter.clone(), ());
    write_voters(e, &voters);
    Ok(())
}

pub fn write_remove_voter(e: &Env, voter: &Address) -> Result<(), UpgradeError> {
    let mut voters = read_voters(e);
    if !voters.contains_key(voter.clone()) {
        return Err(UpgradeError::NotInVotersList);
    }
    if voters.len() <= MIN_GOVERNANCE_VOTERS {
        return Err(UpgradeError::MinimumVotersRequired);
    }
    voters.remove(voter.clone());
    write_voters(e, &voters);
    Ok(())
}

pub fn initialize_voters(e: &Env, voters: &soroban_sdk::Vec<Address>) -> Result<(), UpgradeError> {
    if voters.len() < MIN_GOVERNANCE_VOTERS {
        return Err(UpgradeError::MinimumVotersRequired);
    }
    let mut stored = Map::new(e);
    for voter in voters.iter() {
        if stored.contains_key(voter.clone()) {
            return Err(UpgradeError::DuplicateVoter);
        }
        stored.set(voter, ());
    }
    write_voters(e, &stored);
    Ok(())
}

pub fn require_voter_threshold(
    e: &Env,
    approvals: &soroban_sdk::Vec<Address>,
) -> Result<(), UpgradeError> {
    let (_, threshold, voters) = get_voter_info(e)?;
    if approvals.len() < threshold {
        return Err(UpgradeError::InvalidVoterApprovals);
    }
    let mut seen = Map::new(e);
    for voter in approvals.iter() {
        if !voters.contains_key(voter.clone()) || seen.contains_key(voter.clone()) {
            return Err(UpgradeError::InvalidVoterApprovals);
        }
        voter.require_auth();
        seen.set(voter, ());
    }
    Ok(())
}

pub fn get_voter_info(e: &Env) -> Result<(u32, u32, Map<Address, ()>), UpgradeError> {
    let voters = read_voters(e);
    let voter_count = voters.len();

    if voter_count == 0 {
        return Err(UpgradeError::NotEnoughVoters);
    }

    let threshold = compute_approval_threshold(voter_count);

    Ok((voter_count, threshold, voters))
}

pub fn compute_approval_threshold(voter_count: u32) -> u32 {
    let numerator = voter_count * VOTING_THRESHOLD;
    let mut threshold = numerator / 100;

    if !numerator.is_multiple_of(100) {
        threshold += 1;
    }

    threshold
}

pub fn read_has_upgrade_passed(e: &Env) -> Result<(u32, bool), UpgradeError> {
    let key = DataKey::VotedList;

    let voted: Map<Address, ()> = if let Some(voted) = e.storage().persistent().get(&key) {
        bump_persistent(e, &key);
        voted
    } else {
        Map::new(e)
    };

    let proposal_voters = read_proposal_voters(e)?;
    let required_threshold = read_proposal_approval_threshold(e)?;

    let mut valid_vote_count: u32 = 0;

    for voter in voted.keys() {
        if proposal_voters.contains_key(voter) {
            valid_vote_count += 1;
        }
    }

    Ok((valid_vote_count, valid_vote_count >= required_threshold))
}
