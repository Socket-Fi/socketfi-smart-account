use socketfi_shared::ttl::bump_instance;
use soroban_sdk::{contracttype, Address, Bytes, Env};

/// Shared access/config storage keys.
///
/// DESIGN:
/// - Most addresses here are contract-wide configuration and live in instance storage.
/// - Some identity-related keys are included for compatibility with other modules,
///   even if they are not read/written directly in this file.
///
/// IMPORTANT:
/// - This file provides low-level storage/auth helpers only.
/// - It does not enforce higher-level business rules such as uniqueness between
///   configured addresses or one-time initialization beyond what callers enforce.
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    Admin,
    Factory,
    Registry,
    FeeManager,
    SocialPayments,
    PaymentManager,
    UseridWalletMap(Bytes),
    PasskeyWalletMap(Bytes),
}

// -----------------------------------------------------------------------------
// Admin
// -----------------------------------------------------------------------------

/// Returns `true` if the contract admin has already been initialized.
///
/// DESIGN:
/// - `Admin` acts as the initialization marker for this contract.
/// - Commonly used to prevent constructor re-entry / double initialization.
///
/// AUDIT NOTE:
/// - This assumes initialization is effectively atomic:
///   if `Admin` exists, the contract is treated as initialized.
/// - If initialization ever becomes multi-step, relying only on `Admin` as the
///   initialization marker may become insufficient.
pub fn has_admin(e: &Env) -> bool {
    let key = DataKey::Admin;
    e.storage().instance().has(&key)
}

/// Reads the configured contract admin.
///
/// RETURNS:
/// - `Some(Address)` if admin is set
/// - `None` if admin is not configured
///
/// AUDIT NOTE:
/// - Reads from instance storage, so instance TTL must be maintained if the
///   contract is expected to remain usable long-term.
pub fn read_admin(e: &Env) -> Option<Address> {
    let key = DataKey::Admin;
    bump_instance(e);
    e.storage().instance().get(&key)
}

/// Writes the contract admin to instance storage.
///
/// DESIGN:
/// - Low-level storage helper only.
/// - Does not perform authorization checks.
///
/// AUDIT NOTE:
/// - Must only be called from trusted flows such as:
///   - constructor
///   - authenticated admin update paths
/// - Misuse of this helper in an unprotected path would compromise admin control.
pub fn write_admin(e: &Env, admin: &Address) {
    bump_instance(e);
    let key = DataKey::Admin;
    e.storage().instance().set(&key, admin);
}

/// Requires authorization from the currently configured admin.
///
/// BEHAVIOR:
/// - Reads the stored admin
/// - Calls `require_auth()` on that address
///
/// IMPORTANT:
/// - This function does NOT return `Result`.
/// - It will panic if admin is not configured because it uses `unwrap()`.
///
/// AUDIT NOTE:
/// - Security depends on `read_admin` returning the correct stored admin.
/// - This function does not bump TTL; callers should ensure instance TTL is
///   maintained elsewhere for long-lived contract configuration.
pub fn authenticate_admin(e: &Env) {
    let admin = read_admin(e).unwrap();
    admin.require_auth();
}

// -----------------------------------------------------------------------------
// Factory
// -----------------------------------------------------------------------------

/// Reads the configured factory contract address.
///
/// RETURNS:
/// - `Some(Address)` if factory is set
/// - `None` otherwise
///
/// AUDIT NOTE:
/// - Reads from instance storage; instance TTL must be maintained.
pub fn read_factory(e: &Env) -> Option<Address> {
    let key = DataKey::Factory;
    bump_instance(e);
    e.storage().instance().get(&key)
}

/// Writes the configured factory contract address.
///
/// DESIGN:
/// - Low-level storage helper only.
/// - Does not perform authorization checks.
///
/// AUDIT NOTE:
/// - Must only be called from trusted/admin-controlled flows.
/// - No business-rule validation is enforced here
///   (for example, whether factory equals another configured address).
pub fn write_factory(e: &Env, factory: &Address) {
    let key = DataKey::Factory;
    bump_instance(e);
    e.storage().instance().set(&key, factory);
}

// -----------------------------------------------------------------------------
// Social Payments
// -----------------------------------------------------------------------------

/// Reads the configured social payments contract address.
///
/// RETURNS:
/// - `Some(Address)` if social payments is set
/// - `None` otherwise
///
/// AUDIT NOTE:
/// - Reads from instance storage; instance TTL must be maintained.
pub fn read_social_router(e: &Env) -> Option<Address> {
    let key = DataKey::SocialPayments;
    bump_instance(e);
    e.storage().instance().get(&key)
}

/// Writes the configured social payments contract address.
///
/// DESIGN:
/// - Low-level storage helper only.
/// - Does not perform authorization checks.
///
/// AUDIT NOTE:
/// - Must only be called from trusted/admin-controlled flows.
/// - No business-rule validation is enforced here
///   (for example, uniqueness vs admin/factory or other address constraints).
pub fn write_social_router(e: &Env, social_router: &Address) {
    let key = DataKey::SocialPayments;
    bump_instance(e);
    e.storage().instance().set(&key, social_router);
}

// -----------------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------------

/// Reads the configured registry contract address.
///
/// RETURNS:
/// - `Some(Address)` if registry is set
/// - `None` otherwise
///
/// AUDIT NOTE:
/// - Reads from instance storage; instance TTL must be maintained.
pub fn read_registry(e: &Env) -> Option<Address> {
    let key = DataKey::Registry;
    bump_instance(e);
    e.storage().instance().get(&key)
}

/// Writes the registry contract address to instance storage.
///
/// DESIGN:
/// - Low-level storage helper only.
/// - Does not perform authorization checks.
///
/// AUDIT NOTE:
/// - Caller must enforce authorization where required.
pub fn write_registry(e: &Env, registry: &Address) {
    let key = DataKey::Registry;
    bump_instance(e);
    e.storage().instance().set(&key, registry);
}

// -----------------------------------------------------------------------------
// Fee Manager
// -----------------------------------------------------------------------------

/// Reads the configured fee manager contract address.
///
/// RETURNS:
/// - `Some(Address)` if fee manager is set
/// - `None` otherwise
///
/// AUDIT NOTE:
/// - Reads from instance storage; instance TTL must be maintained.
pub fn read_fee_manager(e: &Env) -> Option<Address> {
    let key = DataKey::FeeManager;
    bump_instance(e);
    e.storage().instance().get(&key)
}

/// Writes the fee manager contract address to instance storage.
///
/// DESIGN:
/// - Low-level storage helper only.
/// - Does not perform authorization checks.
///
/// AUDIT NOTE:
/// - Caller must enforce authorization where required.
pub fn write_fee_manager(e: &Env, fee_manager: &Address) {
    let key = DataKey::FeeManager;
    bump_instance(e);
    e.storage().instance().set(&key, fee_manager);
}
