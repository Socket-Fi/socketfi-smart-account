use crate::errors::UpgradeError;
use crate::storage::{read_proposal_approval_threshold, read_proposal_voters, DataKey};
use socketfi_shared::constants::VOTING_THRESHOLD;
use soroban_sdk::{Address, Env, Map};

pub fn read_voters(e: &Env) -> Map<Address, ()> {
    e.storage()
        .persistent()
        .get(&DataKey::VotersList)
        .unwrap_or(Map::new(e))
}

pub fn write_voters(e: &Env, voters: &Map<Address, ()>) {
    e.storage().persistent().set(&DataKey::VotersList, voters);
}

pub fn write_add_voter(e: &Env, voter: &Address) {
    let mut voters = read_voters(e);
    voters.set(voter.clone(), ());
    write_voters(e, &voters);
}

pub fn write_remove_voter(e: &Env, voter: &Address) {
    let mut voters = read_voters(e);
    voters.remove(voter.clone());
    write_voters(e, &voters);
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

    if numerator % 100 != 0 {
        threshold += 1;
    }

    threshold
}

pub fn read_has_upgrade_passed(e: &Env) -> Result<(u32, bool), UpgradeError> {
    let voted: Map<Address, ()> = e
        .storage()
        .persistent()
        .get(&DataKey::VotedList)
        .unwrap_or(Map::new(e));

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
