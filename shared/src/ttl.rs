use soroban_sdk::{Env, IntoVal, Val};

use crate::constants::{TTL_REFRESH_THRESHOLD_LEDGERS, TTL_TARGET_LEDGERS};

fn bounded_ttl_window(max_ttl: u32) -> (u32, u32) {
    let target = TTL_TARGET_LEDGERS.min(max_ttl);
    let threshold = TTL_REFRESH_THRESHOLD_LEDGERS.min(target);
    (threshold, target)
}

// -----------------------------------------------------------------------------
// Instance TTL
// -----------------------------------------------------------------------------

/// Extends TTL for the contract's instance storage.
///
/// DESIGN:
/// - Refreshes instance storage to the longest supported session lifetime.
/// - Refreshes only when the remaining TTL is below the configured threshold.
/// - Caps both values to the active network's maximum TTL.
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
/// - If the contract is idle beyond the target window, instance state may archive.
///
/// COST NOTE:
/// - Bumping TTL adds cost, so it should be used intentionally on important paths.
pub fn bump_instance(e: &Env) {
    let (threshold, target) = bounded_ttl_window(e.storage().max_ttl());
    e.storage().instance().extend_ttl(threshold, target);
}

// -----------------------------------------------------------------------------
// Persistent TTL
// -----------------------------------------------------------------------------

/// Extends TTL for a persistent storage entry.
///
/// DESIGN:
/// - Intended for long-lived keys such as mappings, registries, and user-linked state.
/// - Extends the TTL of a specific persistent key to the bounded target window.
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
    let (threshold, target) = bounded_ttl_window(e.storage().max_ttl());
    e.storage().persistent().extend_ttl(key, threshold, target);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ttl_window_uses_bounded_policy_on_long_lived_networks() {
        assert_eq!(
            bounded_ttl_window(TTL_TARGET_LEDGERS.saturating_mul(2)),
            (TTL_REFRESH_THRESHOLD_LEDGERS, TTL_TARGET_LEDGERS)
        );
    }

    #[test]
    fn ttl_window_caps_policy_to_network_maximum() {
        let network_max = TTL_REFRESH_THRESHOLD_LEDGERS / 2;
        assert_eq!(bounded_ttl_window(network_max), (network_max, network_max));
    }
}
