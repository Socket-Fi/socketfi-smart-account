use soroban_sdk::{Env, IntoVal, Val};

use crate::constants::DAY_IN_LEDGERS;

// -----------------------------------------------------------------------------
// Instance TTL
// -----------------------------------------------------------------------------

/// Extends TTL for the contract's instance storage.
///
/// DESIGN:
/// - Refreshes instance storage TTL close to the maximum allowed by the network.
/// - Uses `DAY_IN_SECONDS` as a safety buffer to avoid extending at the exact edge.
///
/// IMPORTANT:
/// - This affects INSTANCE storage only.
/// - It does NOT extend persistent entries.
///
/// WHEN TO USE:
/// - In functions that rely on long-lived contract-wide configuration/state.
/// - Especially useful for contracts expected to stay active over time.
///
/// AUDIT NOTE:
/// - TTL extension depends on interaction with the contract.
/// - If the contract is idle for too long, instance state may still expire.
///
/// COST NOTE:
/// - Bumping TTL adds cost, so it should be used intentionally on important paths.
pub fn bump_instance(e: &Env) {
    let max_ttl = e.storage().max_ttl();

    e.storage()
        .instance()
        .extend_ttl(max_ttl - DAY_IN_LEDGERS, max_ttl);
}

// -----------------------------------------------------------------------------
// Persistent TTL
// -----------------------------------------------------------------------------

/// Extends TTL for a persistent storage entry.
///
/// DESIGN:
/// - Intended for long-lived keys such as mappings, registries, and user-linked state.
/// - Extends the TTL of a specific persistent key close to network max TTL.
///
/// IMPORTANT:
/// - This affects only the provided persistent key.
/// - It does NOT extend:
///   - instance storage
///   - other persistent keys
///
/// WHEN TO USE:
/// - On critical read/write paths for keys that should remain alive long-term.
///
/// RISK:
/// - If TTL is not refreshed for important persistent keys, they may expire silently,
///   which can cause missing mappings or inconsistent behavior across contracts.
///
/// COST NOTE:
/// - Frequent TTL bumps increase execution cost.
/// - Should be applied selectively to important keys rather than everywhere.
pub fn bump_persistent<K>(e: &Env, key: &K)
where
    K: IntoVal<Env, Val>,
{
    let max_ttl = e.storage().max_ttl();

    e.storage()
        .persistent()
        .extend_ttl(key, max_ttl - DAY_IN_LEDGERS, max_ttl);
}
