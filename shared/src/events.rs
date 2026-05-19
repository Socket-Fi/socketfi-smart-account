use soroban_sdk::{contractevent, Address, BytesN, Vec};

#[contractevent(topics = ["Upgrade", "ProposalCreated"])]
pub struct UpgradeProposalEvent {
    pub wasm: BytesN<32>,
    pub voting_deadline: u64,
}

#[contractevent(topics = ["Upgrade", "ContractUpgrade"])]
pub struct ContractUpgradeEvent {
    pub wasm: BytesN<32>,
}

#[contractevent(topics = ["Upgrade", "WalletVersion"])]
pub struct WalletVersionUpgradeEvent {
    pub wasm: BytesN<32>,
}

#[contractevent(topics = ["Upgrade", "VoteCast"])]
pub struct VoteEvent {
    pub wasm: BytesN<32>,
    pub voter: Address,
}

#[contractevent(topics = ["Upgrade", "UpgradeCancelled"])]
pub struct UpgradeCancelledEvent {
    pub wasm: BytesN<32>,
}
#[contractevent(topics = ["Wallet", "Creation"])]
pub struct WalletCreationEvent {
    pub wallet: Address,
    pub passkey: BytesN<65>,
   pub bls_keys: Vec<BytesN<96>>,
}
#[contractevent(topics = ["Update", "Admin"])]
pub struct UpdateAdminEvent {
    pub value: Address,
}
#[contractevent(topics = ["Add", "Voter"])]
pub struct AddVoterEvent {
    pub value: Address,
}
#[contractevent(topics = ["Remove", "Voter"])]
pub struct RemoveVoterEvent {
    pub value: Address,
}
#[contractevent(topics = ["Update", "Registry"])]
pub struct UpdateRegistryEvent {
    pub value: Address,
}
#[contractevent(topics = ["Update", "SocialRouter"])]
pub struct UpdateSocialRouterEvent {
    pub value: Address,
}
#[contractevent(topics = ["Update", "FeeManager"])]
pub struct UpdateFeeManagerEvent {
    pub value: Address,
}
