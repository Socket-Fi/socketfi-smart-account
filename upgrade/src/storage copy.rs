use crate::errors::UpgradeError;
use crate::types::UpgradeType;
use soroban_sdk::{contracttype, BytesN, Env, String};

/// Storage keys used by the upgrade governance module.
///
/// -----------------------------------------------------------------------------
/// DESIGN OVERVIEW
/// -----------------------------------------------------------------------------
/// - Only ONE proposal can exist at any time.
/// - Proposal state is stored in instance storage (global, contract-wide).
/// - Voting data (`VotedList`) is stored in persistent storage.
///
/// CORE INVARIANTS:
/// - `FutureWASM` and `ProposalType` MUST always be written together.
/// - `UpgradeVotingDeadline != 0` implies an active proposal exists.
/// - When a proposal is cleared, ALL related state must be removed.
///
/// IMPORTANT:
/// - This module does NOT enforce authorization.
/// - Callers must enforce admin/governance permissions.
///
/// STORAGE SPLIT:
/// - Instance storage → proposal metadata (cheap, global)
/// - Persistent storage → voter participation (per-address state)
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    /// UNIX timestamp after which the pending proposal may be executed.
    ///
    /// NOTE:
    /// - `0` means NO active proposal.
    UpgradeVotingDeadline,

    /// WASM hash currently under vote.
    ///
    /// INVARIANT:
    /// - Must always exist together with `ProposalType`.
    FutureWASM,

    /// Approved voter set.
    ///
    /// NOTE:
    /// - Managed separately (add/remove voter functions).
    VotersList,

    /// Addresses that have voted for the current active proposal.
    ///
    /// DESIGN:
    /// - Global because only one proposal exists at a time.
    /// - Cleared entirely when proposal ends.
    VotedList,

    /// Latest approved wallet version hash.
    ///
    /// NOTE:
    /// - Used when proposal type = WalletVersion.
    /// - Survives across proposals.
    WalletVersion,

    /// Type of the currently active proposal.
    ///
    /// INVARIANT:
    /// - Must always exist together with `FutureWASM`.
    ProposalType,
}

// -----------------------------------------------------------------------------
// Voting Deadline
// -----------------------------------------------------------------------------

/// Returns the active voting deadline.
///
/// RETURNS:
/// - `0` → no active proposal
/// - `> 0` → active proposal exists
///
/// IMPORTANT:
/// - This function is used as the PRIMARY signal for proposal existence.
/// - Other state reads rely on this invariant being respected.
pub fn get_upgrade_voting_deadline(e: &Env) -> u64 {
    e.storage()
        .instance()
        .get(&DataKey::UpgradeVotingDeadline)
        .unwrap_or(0)
}

/// Writes the active voting deadline.
///
/// ASSUMPTION:
/// - Caller ensures no existing active proposal.
/// - Caller sets a valid future timestamp.
pub fn write_upgrade_voting_deadline(e: &Env, value: &u64) {
    e.storage()
        .instance()
        .set(&DataKey::UpgradeVotingDeadline, value);
}

// -----------------------------------------------------------------------------
// Proposal State
// -----------------------------------------------------------------------------

/// Returns the pending proposal WASM hash.
///
/// RETURNS:
/// - `Some(hash)` → active proposal payload
/// - `None` → no proposal or inconsistent state
///
/// NOTE:
/// - Many higher-level functions use `.unwrap()` on this.
/// - This relies on invariant:
///     if deadline != 0 → FutureWASM MUST exist
pub fn read_future_wasm(e: &Env) -> Option<BytesN<32>> {
    e.storage().instance().get(&DataKey::FutureWASM)
}

/// Returns the proposal type.
///
/// RETURNS:
/// - `Some(type)` → valid proposal
/// - `None` → inconsistent or missing state
///
/// NOTE:
/// - Must always exist alongside `FutureWASM`.
pub fn read_proposal_type(e: &Env) -> Option<UpgradeType> {
    e.storage().instance().get(&DataKey::ProposalType)
}

/// Stores a new pending proposal.
///
/// FLOW:
/// 1. Parse string → UpgradeType
/// 2. Store WASM hash
/// 3. Store proposal type
///
/// ERRORS:
/// - `UpgradeTypeNotFound` → invalid proposal type string
///
/// CRITICAL INVARIANT:
/// - `FutureWASM` and `ProposalType` MUST be written together
///
/// SECURITY:
/// - Caller must enforce:
///     - authorization
///     - no existing active proposal
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

// -----------------------------------------------------------------------------
// Wallet Version
// -----------------------------------------------------------------------------

/// Stores the approved wallet implementation hash.
///
/// USED WHEN:
/// - Proposal type = WalletVersion
///
/// NOTE:
/// - This value persists across proposals.
/// - It represents the "current approved wallet implementation".
pub fn write_wallet_wasm_version(e: &Env, wasm_hash: &BytesN<32>) {
    e.storage()
        .instance()
        .set(&DataKey::WalletVersion, wasm_hash);
}

/// Returns the approved wallet implementation hash.
///
/// RETURNS:
/// - `Some(hash)` → wallet version initialized
/// - `None` → not initialized yet
pub fn read_wallet_wasm_version(e: &Env) -> Option<BytesN<32>> {
    e.storage().instance().get(&DataKey::WalletVersion)
}

// -----------------------------------------------------------------------------
// Cleanup
// -----------------------------------------------------------------------------

/// Clears all state associated with the currently active proposal.
///
/// MUST BE CALLED:
/// - after successful execution
/// - after cancellation
/// - after wallet version upgrade
///
/// EFFECT:
/// - Removes proposal metadata (deadline, wasm, type)
/// - Clears ALL votes
///
/// CRITICAL DESIGN:
/// - Because only ONE proposal exists at a time,
///   `VotedList` is global and fully reset.
///
/// SAFETY:
/// - Safe to call even if some keys are missing
/// - Leaves contract in "no active proposal" state
pub fn clear_pending_upgrade_state(e: &Env) {
    e.storage()
        .instance()
        .remove(&DataKey::UpgradeVotingDeadline);
    e.storage().instance().remove(&DataKey::FutureWASM);
    e.storage().instance().remove(&DataKey::ProposalType);

    // Persistent because votes are per-address state
    e.storage().persistent().remove(&DataKey::VotedList);
}
