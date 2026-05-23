use soroban_sdk::{contracttype, Address};

/// - No validation is performed here
#[derive(Clone)]
#[contracttype]
pub struct ProtocolDependencies {
    pub registry: Address,
    pub social_router: Address,
    pub fee_manager: Address,
}
