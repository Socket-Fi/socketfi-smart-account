use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum UpgradeError {
    AlreadyInitialized = 411,
    AnotherUpgradePending = 1001,
    NoPendingUpgradeAction = 1005,
    UpgradeTypeNotFound = 1008,
    VotingClosed = 1009,
    VotingStillOngoing = 1010,
    InvalidUpgradeHash = 1011,
    AlreadyVoted = 1013,
    NotInVotersList = 1025,
    DidNotPass = 1027,
    NotEnoughVoters = 1037,
    NotFound = 1047,
    InvalidNetwork = 1048,
    DuplicateVoter = 1049,
    MinimumVotersRequired = 1050,
    InvalidVoterApprovals = 1051,
    WasmAlreadyApproved = 1052,
    ArithmeticOverflow = 1053,
    AdminMustBeVoter = 1054,
}
