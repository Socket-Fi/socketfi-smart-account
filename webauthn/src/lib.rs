#![no_std]

use soroban_sdk::{Bytes, BytesN, Env};
use wallet_error::WalletError;
use webauth_helper::{ascii_bytes, base64url_encode_no_pad, json_string_field_equals};
pub mod wallet_error;
pub mod webauth_helper;

// Maximum accepted WebAuthn `clientDataJSON` size.
///
/// This bounds parsing cost and prevents oversized client-controlled payloads
/// from increasing on-chain execution cost.
pub const MAX_CLIENT_DATA_JSON_LEN: u32 = 4096;

/// Validates WebAuthn `clientDataJSON` against the expected assertion challenge.
///
/// Checks that:
/// - `type` is exactly `webauthn.get`
/// - `challenge` matches the Base64URL-no-padding encoding of `challenge`
/// - payload size is within `MAX_CLIENT_DATA_JSON_LEN`
///
/// Returns the encoded challenge and original client data for downstream digest
/// construction.
fn __verify_webauthn_client_data(
    env: &Env,
    challenge: BytesN<32>,
    client_data_json: Bytes,
) -> Result<(), WalletError> {
    if client_data_json.len() > MAX_CLIENT_DATA_JSON_LEN {
        return Err(WalletError::ClientDataTooLarge);
    }

    let webauthn_get = ascii_bytes(env, b"webauthn.get");

    if !json_string_field_equals(env, &client_data_json, b"type", &webauthn_get) {
        return Err(WalletError::InvalidClientDataType);
    }

    let encoded_challenge = base64url_encode_no_pad(env, &challenge.into());

    if !json_string_field_equals(env, &client_data_json, b"challenge", &encoded_challenge) {
        return Err(WalletError::InvalidChallenge);
    }

    Ok(())
}

/// Validates authenticator data security properties for a passkey assertion.
///
/// Checks that:
/// - RP ID hash matches the expected relying party hash
/// - User Presence flag is set
/// - User Verification flag is set
///
/// This function assumes `authenticator_data` contains at least 33 bytes:
/// 32 bytes RP ID hash followed by the flags byte.
fn __verify_authenticator_data(
    expected_rpid_hash: BytesN<32>,
    authenticator_data: &Bytes,
) -> Result<(), WalletError> {
    if authenticator_data.len() < 33 {
        return Err(WalletError::InvalidAuthenticatorData);
    }
    let flags = authenticator_data.get_unchecked(32);

    if (flags & 0x01) == 0 {
        return Err(WalletError::UserPresenceRequired);
    }

    if (flags & 0x04) == 0 {
        return Err(WalletError::UserVerificationRequired);
    }

    let mut i = 0;
    while i < 32 {
        if authenticator_data.get_unchecked(i) != expected_rpid_hash.get_unchecked(i) {
            return Err(WalletError::InvalidRpIdHash);
        }

        i += 1;
    }

    Ok(())
}

/// Validates passkey assertion metadata and challenge binding prior to
/// cryptographic signature verification.
///
/// This function verifies:
/// - WebAuthn assertion type (`webauthn.get`)
/// - challenge binding
/// - RP ID hash binding
/// - User Presence (UP)
/// - User Verification (UV)
///
/// This function does not verify the passkey signature itself.
pub fn __validate_passkey_assertion_data(
    env: &Env,
    challenge: BytesN<32>,
    expected_rpid_hash: BytesN<32>,
    authenticator_data: Bytes,
    client_data_json: Bytes,
) -> Result<(), WalletError> {
    __verify_webauthn_client_data(env, challenge, client_data_json)?;

    __verify_authenticator_data(expected_rpid_hash, &authenticator_data)?;

    Ok(())
}
