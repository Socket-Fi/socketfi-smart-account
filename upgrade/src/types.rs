use soroban_sdk::{contracttype, String};

/// Represents the type of upgrade proposal.
///
/// VARIANTS:
/// - Upgrade → contract WASM upgrade
/// - WalletVersion → update approved wallet implementation hash
///
/// DESIGN NOTE:
/// - This enum is persisted in storage via `ProposalType`.
/// - Must remain backward-compatible across contract upgrades.
///
/// IMPORTANT:
/// - Adding new variants in future requires:
///   - updating parsing logic (`upgrade_type`)
///   - ensuring backward compatibility with stored values
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpgradeType {
    Upgrade,
    WalletVersion,
}

impl UpgradeType {
    /// Parses a string into an `UpgradeType`.
    ///
    /// INPUT:
    /// - Expected values:
    ///     - "upgrade"
    ///     - "wallet"
    ///
    /// RETURNS:
    /// - Some(UpgradeType) → valid type
    /// - None → invalid/unsupported type
    ///
    /// IMPORTANT:
    /// - Matching is STRICT and case-sensitive.
    /// - Any mismatch (e.g. "Upgrade", "WALLET") will fail.
    ///
    /// SECURITY:
    /// - Prevents invalid proposal types from entering storage.
    ///
    /// GAS NOTE:
    /// - Reconstructs `String` values each call (acceptable due to small size).
    ///
    /// DESIGN ASSUMPTION:
    /// - Input strings come from trusted or validated sources
    ///   (e.g. frontend or controlled contract calls).
    pub fn upgrade_type(s: String) -> Option<Self> {
        let e = s.env();

        if s == String::from_str(&e, "upgrade") {
            Some(Self::Upgrade)
        } else if s == String::from_str(&e, "wallet") {
            Some(Self::WalletVersion)
        } else {
            None
        }
    }
}
