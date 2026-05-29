use soroban_sdk::{contracttype, Address, Bytes};
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Validators,
    RegistryManager(Address),
    HasMap(Bytes),
}
