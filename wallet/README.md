# Wallet Contract

The **Wallet Contract** is SocketFi's smart account implementation for Soroban.

It provides passkey-native authentication, guardian-based account recovery, emergency pause controls, and programmable transaction authorization through Soroban's native smart account interface.

---

# Overview

The Wallet contract is responsible for:

- Managing wallet authentication using passkeys
- Recovering accounts through guardian BLS signatures
- Executing authenticated contract invocations
- Protecting compromised wallets through guardian pause controls
- Managing the wallet's guardian set

---

# Features

## Passkey Authentication

- Native passkey authentication
- WebAuthn proof-of-possession verification
- Passkey rotation
- Soroban `__check_auth` implementation

## Guardian Recovery

- Aggregate BLS recovery authorization
- Recovery without the original passkey
- Secure passkey replacement
- Configurable guardian set

## Emergency Protection

- Guardian-triggered wallet pause
- Guardian approval required before unpausing
- Prevents unauthorized wallet usage during compromise

## Guardian Management

- Add guardians
- Schedule guardian removal
- Delayed guardian removal finalization

---

# Initialization

## `__constructor`

Initializes a newly deployed wallet.

### Parameters

- `challenge: BytesN<32>`
- `passkey: BytesN<65>`
- `passkey_sig: PasskeySignature`
- `rpid_hash: BytesN<32>`
- `bls_keys_pop: Vec<BlsKeyWithPoP>`
- `guardians: Vec<Address>`

During initialization the wallet:

- Verifies passkey proof of possession
- Verifies every guardian BLS proof of possession
- Aggregates the guardian BLS public key
- Stores the passkey and RP ID hash
- Initializes guardian state
- Starts in the unpaused state

---

# Core Functions

## `rotate_passkey`

Replaces the current passkey.

Requires:

- Wallet authentication
- Valid proof of possession for the new passkey

---

## `recover_account`

Recovers the wallet by installing a new passkey.

Requires:

- Valid proof of possession for the new passkey
- Valid aggregate BLS recovery signature

---

## `pause`

Allows an authorized guardian to immediately pause the wallet.

Pausing prevents normal wallet operation until recovery or approval to resume.

---

## `approve_unpause`

Records guardian approval to resume wallet activity.

---

## `unpause`

Removes the paused state.

Requires:

- Wallet authentication
- Guardian approval

---

## `add_guardian`

Adds a new guardian to the wallet.

---

## `schedule_guardian_removal`

Schedules removal of an existing guardian.

---

## `finalize_guardian_removal`

Completes a previously scheduled guardian removal after the required delay.

---

## Read Functions

### `is_paused`

Returns whether the wallet is currently paused.

### `get_passkey`

Returns the currently registered passkey.

---

# Authentication

The Wallet implements Soroban's `CustomAccountInterface`.

Every authenticated contract invocation passes through `__check_auth`, which:

- Validates the authorization context
- Verifies the passkey signature
- Authorizes the requested operation

This enables the wallet to function as a native Soroban smart account.

---

# Security

The Wallet provides multiple layers of protection:

- Passkey-based authentication
- Proof-of-possession verification
- Aggregate guardian BLS recovery
- Emergency guardian pause
- Two-step unpause process
- Delayed guardian removal
- Authorization context validation

---

# Contract Relationships

```
Factory
    │
    └──── deploys ─────► Wallet
                              │
                              ├── uses Shared
                              └── implements CustomAccountInterface
```

---

# Design Principles

- Passkey-first authentication
- Self-custodial smart accounts
- Guardian-assisted recovery
- Modular security architecture
- Soroban-native account abstraction

---

# Notes

- Wallet deployment is handled by the Factory contract.
- Recovery does not require the original passkey.
- Guardian recovery is authorized using the stored aggregate BLS public key.
- Every authenticated invocation is validated through Soroban's native smart account interface.

---

# License

MIT
