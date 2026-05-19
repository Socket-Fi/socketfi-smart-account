# SocketFi WebAuthn Passkey Assertion Validation

Minimal Soroban `no_std` helper module for validating WebAuthn passkey assertion data on-chain.

## Purpose

This module validates the non-signature parts of a WebAuthn passkey assertion before cryptographic signature verification.

It checks:

- `clientDataJSON.type == "webauthn.get"`
- `clientDataJSON.challenge` matches the expected challenge
- `clientDataJSON` size is bounded
- `authenticatorData` contains the expected RP ID hash
- User Presence (UP) flag is set
- User Verification (UV) flag is set

## Important Security Boundary

`__validate_passkey_assertion_data` does **not** verify the passkey signature.

Signature verification must be performed separately using the digest:

```text
sha256(authenticatorData || sha256(clientDataJSON))
```
