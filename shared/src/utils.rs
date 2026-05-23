use soroban_sdk::{contracttype, Bytes, BytesN, Env, String};

use crate::registry_errors::RegistryError;
use crate::{constants::MAX_LEN, registry_types::SocialPlatform};

/// Storage keys derived from normalized identity inputs.
///
/// DESIGN:
/// - `UseridWalletMap` stores mappings derived from `(platform, user_id)`
/// - `PasskeyWalletMap` stores mappings derived from raw passkey bytes
///
/// IMPORTANT:
/// - These keys depend on the exact hashing/domain-separation logic below.
/// - Changing encoding, validation, or domain strings will break compatibility
///   with existing stored mappings.
#[derive(Clone)]
#[contracttype]
pub enum DataKey {
    UseridWalletMap(Bytes),
    PasskeyWalletMap(Bytes),
}

// -----------------------------------------------------------------------------
// User ID Validation
// -----------------------------------------------------------------------------

/// Validates a user identity string (`user_id`) used for platform bindings.
///
/// VALIDATION RULES:
/// - Must not be empty
/// - Must not exceed `MAX_LEN`
/// - Must not contain uppercase ASCII letters (`A-Z`)
/// - Must not contain ASCII whitespace:
///   - space (32)
///   - tab (9)
///   - newline (10)
///   - vertical tab (11)
///   - form feed (12)
///   - carriage return (13)
///
/// DESIGN:
/// - Uses raw UTF-8 bytes (`String -> Bytes`) rather than XDR so validation
///   applies directly to the user input bytes.
/// - Enforces a canonical representation:
///   - lowercase ASCII only
///   - no ASCII whitespace
///   - bounded length
///
/// CRITICAL NOTE:
/// - This function is part of the canonicalization layer and should be applied
///   consistently before:
///   - key derivation
///   - signature message construction
///   - identity comparison
///
/// RISK:
/// - Inconsistent canonicalization can lead to:
///   - mismatched storage keys
///   - signature verification failures
///   - duplicate logical identities (for example, `"Alice"` vs `"alice"`)
///
/// UTF-8 NOTE:
/// - Non-ASCII characters are currently allowed unless restricted elsewhere.
/// - If strict ASCII-only identities are required, enforce `v <= 127`.
///
/// SECURITY NOTE:
/// - Allowing Unicode can introduce homoglyph risks, where visually similar
///   characters represent different byte values.
///
/// PERFORMANCE:
/// - Uses `get_unchecked`, which is safe here because iteration is bounded by `len`.
pub fn validate_userid(id: String) -> Result<(), RegistryError> {
    let id_bytes: Bytes = id.into();
    let len = id_bytes.len();

    if len == 0 {
        return Err(RegistryError::InvalidUserId);
    }

    if len > MAX_LEN {
        return Err(RegistryError::MaxLengthExceeded);
    }

    for i in 0..len {
        let v = id_bytes.get_unchecked(i);

        if v >= 65 && v <= 90 {
            return Err(RegistryError::UpperNotAllowed);
        }

        if matches!(v, 9 | 10 | 11 | 12 | 13 | 32) {
            return Err(RegistryError::SpacesNotAllowed);
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// (platform, user_id) -> wallet mapping key
// -----------------------------------------------------------------------------

/// Derives the storage key for a `(platform, user_id) -> wallet` mapping.
///
/// STRUCTURE:
///   `hash("userid_wallet" || 0x00 || platform || 0x00 || user_id)`
///
/// DESIGN:
/// - Platform is normalized through `SocialPlatform::is_platform_supported`
/// - `user_id` is validated before hashing
/// - Raw bytes are used instead of XDR
/// - `0x00` separators are used to prevent concatenation ambiguity
/// - `"userid_wallet"` provides domain separation for this key namespace
///
/// SECURITY:
/// - Deterministic derivation depends on:
///   - strict validation
///   - canonical platform normalization
///   - stable ordering and separators
///
/// - `0x00` separators prevent ambiguity:
///   - `("ab", "c")` ≠ `("a", "bc")`
///
/// - Hashing provides:
///   - fixed-size derived keys
///   - no direct exposure of raw identity strings in storage keys
///
/// COMPATIBILITY:
/// - Any change to:
///   - validation rules
///   - platform normalization
///   - field order
///   - domain string
///   will break compatibility with previously stored mappings.
///
/// NON-GOALS:
/// - Does not enforce rebinding policy
/// - Does not enforce replay protection
///
/// Those must be handled at higher layers.
pub fn userid_wallet_key(
    e: &Env,
    platform_str: String,
    user_id: String,
) -> Result<DataKey, RegistryError> {
    let platform = SocialPlatform::is_platform_supported(platform_str)?;

    validate_userid(user_id.clone())?;

    let mut salt = Bytes::new(e);

    salt.append(&String::from_str(e, "userid_wallet").into());
    salt.push_back(0);

    salt.append(&String::from_str(e, platform.as_str()).into());
    salt.push_back(0);

    salt.append(&user_id.into());

    Ok(DataKey::UseridWalletMap(e.crypto().sha256(&salt).into()))
}

// -----------------------------------------------------------------------------
// passkey -> wallet mapping key
// -----------------------------------------------------------------------------

/// Derives the storage key for a `passkey -> wallet` mapping.
///
/// STRUCTURE:
///   `hash("passkey_wallet" || 0x00 || passkey_bytes)`
///
/// DESIGN:
/// - Uses a distinct domain separator: `"passkey_wallet"`
/// - Uses raw `BytesN<65>` passkey bytes
/// - Uses `0x00` separator for structured encoding
///
/// SECURITY:
/// - Ensures this namespace does not overlap with `(platform, user_id)` mappings
/// - Passkeys use strict byte equality; no normalization is performed
/// - Hashing provides fixed-size keys and avoids storing raw passkey bytes as keys
///
/// COMPATIBILITY:
/// - Any change to encoding or domain separation will break existing mappings.
pub fn passkey_wallet_key(e: &Env, passkey: BytesN<65>) -> Result<DataKey, RegistryError> {
    let mut salt = Bytes::new(e);

    salt.append(&String::from_str(e, "passkey_wallet").into());
    salt.push_back(0);

    salt.append(&passkey.into_bytes());

    Ok(DataKey::PasskeyWalletMap(e.crypto().sha256(&salt).into()))
}

// -----------------------------------------------------------------------------
// (platform, user_id) payment key
// -----------------------------------------------------------------------------

/// Derives a deterministic payment key from `(platform, user_id)`.
///
/// STRUCTURE:
///   `hash("userid_wallet" || 0x00 || platform || 0x00 || user_id)`
///
/// NOTE:
/// - This uses the SAME domain and encoding as `userid_wallet_key`.
/// - As a result, the returned hash is the same underlying derived identifier
///   used for `UseridWalletMap`, just returned directly as `BytesN<32>`.
///
/// IMPORTANT:
/// - This is safe if the value is used as an identifier only.
/// - If a separate namespace is needed in the future, this function would need
///   its own domain string (for example, `"userid_payment"`).
///
/// COMPATIBILITY:
/// - Changing domain or encoding breaks all previously derived payment keys.
pub fn userid_payment_key(
    e: &Env,
    platform_str: String,
    user_id: String,
) -> Result<BytesN<32>, RegistryError> {
    let platform = SocialPlatform::is_platform_supported(platform_str)?;

    validate_userid(user_id.clone())?;

    let mut salt = Bytes::new(e);

    salt.append(&String::from_str(e, "userid_wallet").into());
    salt.push_back(0);

    salt.append(&String::from_str(e, platform.as_str()).into());
    salt.push_back(0);

    salt.append(&user_id.into());

    Ok(e.crypto().sha256(&salt).into())
}
