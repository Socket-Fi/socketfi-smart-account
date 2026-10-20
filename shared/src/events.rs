use soroban_sdk::{contractevent, Address, BytesN, Vec};

use crate::key_types::{AccountCommitment, BindingType};

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

#[contractevent(topics = ["Binding", "Added"])]
pub struct BindingAddedEvent {
    pub binding_type: BindingType,
    pub commitment: AccountCommitment,
    pub auth_config_nonce: u64,
}

#[contractevent(topics = ["Binding", "Rotated"])]
pub struct BindingRotatedEvent {
    pub binding_type: BindingType,
    pub previous: AccountCommitment,
    pub replacement: AccountCommitment,
    pub auth_config_nonce: u64,
    pub session_epoch: u64,
}

#[contractevent(topics = ["Binding", "Removed"])]
pub struct BindingRemovedEvent {
    pub binding_type: BindingType,
    pub previous: AccountCommitment,
    pub auth_config_nonce: u64,
    pub session_epoch: u64,
}

#[contractevent(topics = ["Binding", "Recovered"])]
pub struct BindingRecoveredEvent {
    pub binding_type: BindingType,
    pub previous: AccountCommitment,
    pub replacement: AccountCommitment,
    pub via_bls: bool,
    pub auth_config_nonce: u64,
    pub session_epoch: u64,
}

#[contractevent(topics = ["Session", "Created"])]
pub struct SessionCreatedEvent {
    pub policy_id: BytesN<32>,
    pub delegate: BytesN<32>,
    pub valid_after_ledger: u32,
    pub expires_at_ledger: u32,
    pub epoch: u64,
}

#[contractevent(topics = ["Session", "Revoked"])]
pub struct SessionRevokedEvent {
    pub policy_id: BytesN<32>,
}

#[contractevent(topics = ["Session", "AllRevoked"])]
pub struct AllSessionsRevokedEvent {
    pub epoch: u64,
}

#[contractevent(topics = ["Guardian", "Added"])]
pub struct GuardianAddedEvent {
    pub guardian: Address,
}

#[contractevent(topics = ["Guardian", "RemovalScheduled"])]
pub struct GuardianRemovalScheduledEvent {
    pub guardian: Address,
    pub removal_ledger: u32,
}

#[contractevent(topics = ["Guardian", "Removed"])]
pub struct GuardianRemovedEvent {
    pub guardian: Address,
}

#[contractevent(topics = ["Account", "Paused"])]
pub struct AccountPausedEvent {
    pub guardian: Address,
}

#[contractevent(topics = ["Account", "UnpauseApproved"])]
pub struct UnpauseApprovedEvent {
    pub guardian: Address,
}

#[contractevent(topics = ["Account", "Unpaused"])]
pub struct AccountUnpausedEvent {}

#[contractevent(topics = ["Account", "Migrated"])]
pub struct AccountMigratedEvent {
    pub wasm: BytesN<32>,
    pub auth_config_nonce: u64,
    pub session_epoch: u64,
}

#[contractevent(topics = ["Factory", "AccountRegistered"])]
pub struct AccountRegisteredEvent {
    pub account: Address,
    pub network: soroban_sdk::Symbol,
    pub nonce: BytesN<32>,
    pub wasm: BytesN<32>,
}
