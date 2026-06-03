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
}
