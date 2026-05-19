use crate::errors::UpgradeError;
use crate::storage::{get_upgrade_voting_deadline, DataKey};
use socketfi_shared::constants::VOTING_THRESHOLD;
use soroban_sdk::{Address, Env, Map, Vec};

// -----------------------------------------------------------------------------
// Voter Membership
// -----------------------------------------------------------------------------

/// Returns `true` if `voter` is in the approved voter set.
///
/// NOTE:
/// - Voters are stored in persistent storage as `Map<Address, ()>`.
/// - This function returns `false` if the voter list has not been initialized yet.
pub fn read_is_voter(env: &Env, voter: Address) -> bool {
    let key = DataKey::VotersList;
    let voters: Map<Address, ()> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Map::new(env));

    voters.contains_key(voter)
}

/// Adds a voter to the approved voter set.
///
/// BEHAVIOR:
/// - If the voter is already present, this function does nothing.
/// - Otherwise, the voter is inserted into the persistent voter map.
///
/// IMPORTANT:
/// - This function does NOT return an error on duplicates.
/// - Caller should enforce authorization before calling this helper.
pub fn write_add_voter(env: &Env, voter: &Address) {
    if read_is_voter(env, voter.clone()) {
        return;
    }

    let key = DataKey::VotersList;
    let mut voters: Map<Address, ()> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Map::new(env));

    voters.set(voter.clone(), ());
    env.storage().persistent().set(&key, &voters);
}

/// Removes a voter from the approved voter set.
///
/// BEHAVIOR:
/// - If the voter is not present, this function does nothing.
/// - Otherwise, the voter is removed from the persistent voter map.
///
/// IMPORTANT:
/// - This function does NOT return an error if the voter is absent.
/// - Caller should enforce authorization before calling this helper.
pub fn write_remove_voter(env: &Env, voter: &Address) {
    if !read_is_voter(env, voter.clone()) {
        return;
    }

    let key = DataKey::VotersList;
    let mut voters: Map<Address, ()> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or(Map::new(env));

    voters.remove(voter.clone());
    env.storage().persistent().set(&key, &voters);
}

/// Returns the full voter list.
///
/// NOTE:
/// - If no voter set exists yet, returns an empty vector.
/// - Order is derived from map key ordering and should not be relied on for governance logic.
pub fn read_voters_list(env: &Env) -> Vec<Address> {
    let key = DataKey::VotersList;

    let m = env
        .storage()
        .persistent()
        .get::<_, soroban_sdk::Map<Address, ()>>(&key)
        .unwrap_or_else(|| soroban_sdk::Map::new(env));

    m.keys()
}

/// Returns the total number of registered voters.
///
/// NOTE:
/// - Derived from `read_voters_list`.
/// - This is an internal helper.
fn read_voter_count(env: &Env) -> u32 {
    let voters = read_voters_list(env);
    voters.len()
}

// -----------------------------------------------------------------------------
// Threshold Calculation
// -----------------------------------------------------------------------------

/// Returns `(total_voters, passing_threshold)`.
///
/// THRESHOLD RULE:
/// - `VOTING_THRESHOLD` is interpreted as a percentage integer.
/// - Threshold is rounded up using:
///   `ceil(total * VOTING_THRESHOLD / 100)`
///
/// EXAMPLE with `VOTING_THRESHOLD = 75`:
/// - 1 voter  -> 1 required
/// - 2 voters -> 2 required
/// - 3 voters -> 3 required
/// - 4 voters -> 3 required
///
/// IMPORTANT:
/// - If there are 0 voters, this returns `(0, 0)`.
/// - Arithmetic overflow causes a panic via `expect("invalid threshold")`.
/// - This function does NOT return `Result`; callers rely on configured constants
///   being valid and small enough for safe arithmetic.
pub fn get_voter_info(env: &Env) -> (u32, u32) {
    let total = read_voter_count(env);

    let threshold = total
        .checked_mul(VOTING_THRESHOLD)
        .and_then(|v| v.checked_add(99))
        .expect("invalid threshold")
        / 100;

    (total, threshold)
}

// -----------------------------------------------------------------------------
// Proposal Vote Status
// -----------------------------------------------------------------------------

/// Returns `(vote_count, has_passed)` for the current active proposal.
///
/// REQUIREMENTS:
/// - There must be an active proposal (`UpgradeVotingDeadline != 0`).
///
/// DESIGN NOTE:
/// - Because only one active proposal is supported at a time,
///   `VotedList` is global to the active proposal.
///
/// IMPORTANT:
/// - If there are zero registered voters, `get_voter_info()` returns threshold `0`,
///   so `has_passed` becomes `true` whenever a proposal exists.
/// - Whether that is acceptable depends on higher-level governance assumptions.
///
/// ERRORS:
/// - `NoPendingUpgradeAction` if there is no active proposal.
pub fn read_has_upgrade_passed(e: &Env) -> Result<(u32, bool), UpgradeError> {
    let deadline = get_upgrade_voting_deadline(e);
    if deadline == 0 {
        return Err(UpgradeError::NoPendingUpgradeAction);
    }

    let (_, threshold) = get_voter_info(e);
    let key = DataKey::VotedList;

    let voted: Map<Address, ()> = e.storage().persistent().get(&key).unwrap_or(Map::new(e));
    let vote_count = voted.len();

    Ok((vote_count, vote_count >= threshold))
}
