use soroban_sdk::{contractevent, Address, BytesN, Vec};

use crate::key_types::AccountCommitment;

#[contractevent(topics = ["Upgrade", "ProposalCreated"])]
pub struct UpgradeProposalEvent {
    pub wasm: BytesN<32>,
    pub voting_deadline: u64,
}

#[contractevent(topics = ["Upgrade", "ContractUpgrade"])]
pub struct ContractUpgradeEvent {
    pub wasm: BytesN<32>,
}

#[contractevent(topics = ["Upgrade", "AccountVersion"])]
pub struct AccountVersionUpgradeEvent {
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
#[contractevent(topics = ["Account", "Creation"])]
pub struct AccountCreationEvent {
    pub account: Address,
    pub passkey: Option<BytesN<65>>,
    pub stellar_signer: Option<BytesN<32>>,
    pub evm_signer: Option<BytesN<20>>,
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

#[contractevent(topics = ["Account", "Rotation"])]
pub struct AccountRotationEvent {
    pub commitment: AccountCommitment,
    pub live_until_ledger: u32,
    pub new_session_epoch: u64,
}
#[contractevent(topics = ["Account", "Recovery"])]
pub struct AccountRecoveryEvent {
    pub commitment: AccountCommitment,
    pub live_until_ledger: u32,
    pub new_session_epoch: u64,
}
