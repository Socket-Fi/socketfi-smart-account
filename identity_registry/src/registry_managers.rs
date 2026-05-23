use socketfi_shared::registry_errors::RegistryError;
use soroban_sdk::{Address, Env};

use crate::data::DataKey;

pub fn write_add_registry_manager(e: &Env, manager: Address) {
    e.storage()
        .persistent()
        .set(&DataKey::RegistryManager(manager), &true);
}

pub fn write_remove_registry_manager(e: &Env, manager: Address) {
    e.storage()
        .persistent()
        .remove(&DataKey::RegistryManager(manager));
}

pub fn read_is_registry_manager(e: &Env, manager: Address) -> bool {
    e.storage()
        .persistent()
        .get::<_, bool>(&DataKey::RegistryManager(manager))
        .unwrap_or(false)
}

pub fn require_registry_manager(e: &Env, manager: Address) -> Result<(), RegistryError> {
    if !read_is_registry_manager(e, manager.clone()) {
        return Err(RegistryError::NotRegistryManager);
    }
    manager.require_auth();

    Ok(())
}
