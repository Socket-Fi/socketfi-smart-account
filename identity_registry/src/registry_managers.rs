use socketfi_shared::{registry_errors::RegistryError, ttl::bump_persistent};
use soroban_sdk::{Address, Env};

use crate::data::DataKey;

pub fn write_add_registry_manager(e: &Env, manager: Address) {
    let key = DataKey::RegistryManager(manager);
    e.storage().persistent().set(&key, &true);
    bump_persistent(e, &key);
}

pub fn write_remove_registry_manager(e: &Env, manager: Address) {
    e.storage()
        .persistent()
        .remove(&DataKey::RegistryManager(manager));
}

pub fn read_is_registry_manager(e: &Env, manager: Address) -> bool {
    let key = DataKey::RegistryManager(manager);

    if let Some(is_manager) = e.storage().persistent().get::<_, bool>(&key) {
        bump_persistent(e, &key);
        is_manager
    } else {
        false
    }
}

pub fn require_registry_manager(e: &Env, manager: Address) -> Result<(), RegistryError> {
    if !read_is_registry_manager(e, manager.clone()) {
        return Err(RegistryError::NotRegistryManager);
    }
    manager.require_auth();

    Ok(())
}
