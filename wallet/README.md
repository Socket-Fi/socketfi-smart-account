# Wallet Contract

The **Wallet Contract** is a programmable smart wallet in the SocketFi ecosystem.

It enables secure asset management, identity-linked interactions, and advanced transaction execution using passkeys and optional BLS signatures.

---

## Overview

The Wallet contract is responsible for:

- Holding and managing user assets
- Executing authorized transactions
- Integrating with identity (registry) and fee systems
- Supporting advanced authentication (passkey + BLS)

---

## Features

### Authentication

- Passkey-based authorization
- Optional BLS signature support
- Flexible signature validation logic

### Asset Management

- Send and receive supported assets
- Token transfers via Soroban token interface
- Safe approval and allowance handling

### Payments

- Deterministic payment ID generation
- Support for social/identity-based payments
- Pending and completed payment tracking

### Integration

- Identity resolution via registry contract
- Fee handling via fee manager
- Cross-contract invocation support

---

## Initialization

### `__constructor`

Initializes the wallet instance.

**Parameters:**

- `passkey: BytesN<65>`
- `bls_keys: Vec<BytesN<96>>`

**Notes:**

- Set during deployment via Factory
- Defines wallet authentication configuration

---

## Core Functions

### `execute`

Executes authorized transactions.

- Validates authentication (passkey / BLS)
- Performs contract calls or token transfers

---

### `send_asset`

Transfers assets from the wallet.

**Params:**

- `to: Address`
- `asset: Address`
- `amount: i128`

---

### `approve`

Approves asset allowance for a spender.

---

### Payment Functions

- Create and manage payments
- Track payment status (pending, completed)
- Generate deterministic payment IDs

---

## Data Model

Typical stored data includes:

- Passkey
- BLS public keys
- Pending payments
- Payment statuses

---

## Security

- Strict authentication required for execution
- Supports multi-signature via BLS keys
- Prevents unauthorized asset transfers
- Safe cross-contract call handling

---

## Integration

Used with:

- Factory → deployment
- Identity Registry → resolve user identities
- Fee Manager → transaction fee handling
- Token contracts → asset transfers

---

## Notes

- Designed for extensibility and upgradeability
- Payment logic relies on deterministic hashing
- Ensure proper validation of external contract calls

---

## License

MIT
