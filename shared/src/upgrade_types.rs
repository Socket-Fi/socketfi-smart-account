use soroban_sdk::{contracttype, String};

// -----------------------------------------------------------------------------
// Upgrade Type
// -----------------------------------------------------------------------------

/// Represents the type of upgrade proposal.
///
/// VARIANTS:
/// - `Upgrade` → upgrade the current contract WASM
/// - `AccountVersion` → update approved account implementation hash
///
/// DESIGN:
/// - Persisted in contract storage (`ProposalType`)
/// - Used to determine execution path during proposal finalization
///
/// CRITICAL COMPATIBILITY NOTE:
/// - This enum is stored on-chain.
/// - DO NOT:
///     - reorder variants
///     - remove existing variants
///
/// - Adding new variants requires:
///     - updating parsing logic (`upgrade_type`)
///     - ensuring existing stored values remain valid
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpgradeType {
    Upgrade,
    AccountVersion,
}

impl UpgradeType {
    /// Parses a string into an `UpgradeType`.
    ///
    /// INPUT:
    /// - Expected lowercase values:
    ///     - "upgrade"
    ///     - "account"
    ///
    /// RETURNS:
    /// - `Some(UpgradeType)` → valid type
    /// - `None` → unsupported/invalid type
    ///
    /// IMPORTANT:
    /// - Matching is STRICT and case-sensitive.
    ///     - "upgrade" → valid
    ///     - "Upgrade" → invalid
    ///
    /// SECURITY:
    /// - Prevents invalid proposal types from being stored
    ///
    /// DESIGN ASSUMPTION:
    /// - Input is normalized by caller (frontend / API / contract entrypoint)
    ///
    /// GAS NOTE:
    /// - Constructs temporary `String` values for comparison
    /// - Cost is minimal due to small input size
    // Keep the existing public Rust helper name for downstream callers.
    #[allow(clippy::self_named_constructors)]
    pub fn upgrade_type(s: String) -> Option<Self> {
        let e = s.env();

        if s == String::from_str(e, "upgrade") {
            Some(Self::Upgrade)
        } else if s == String::from_str(e, "account") {
            Some(Self::AccountVersion)
        } else {
            None
        }
    }
}
