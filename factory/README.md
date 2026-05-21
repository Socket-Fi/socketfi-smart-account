# Factory Contract

The **Factory Contract** is the deployment and governance entry point for wallet creation in the SocketFi ecosystem.

It manages wallet deployment, system dependencies, and upgrade coordination.

---

## Overview

The Factory contract is responsible for:

- Deploying new wallet instances
- Storing shared protocol dependencies
- Managing the active wallet WASM version
- Coordinating upgrade governance

---

## Features

### Wallet Deployment

- Permissionless wallet creation
- Initializes wallets with passkey and optional BLS keys
- Uses the currently approved wallet WASM

### System Configuration

Stores core dependencies:

- Admin
- Registry contract
- Fee manager contract
- (Optional) Social router

### Upgrade Governance

- Proposal-based wallet upgrades
- Approved voter participation
- Controlled upgrade execution

---

## Initialization

### `__constructor`

Initializes the contract.

**Parameters:**

- `admin: Address`
- `registry: Address`
- `fee_manager: Address`
- `wasm: BytesN<32>`

(Optional if implemented)

- `social_router: Address`

**Notes:**

- Can only be called once
- Sets initial wallet version and dependencies

---

## Core Functions

### `create_wallet`

Deploys a new wallet instance.

**Params:**

- `passkey: BytesN<77>`
- `bls_keys: Vec<BytesN<96>>`

**Returns:**

- `Address`

---

### Read Methods

- `get_wallet_wasm_hash`
- `get_admin`
- `get_registry`
- `get_fee_manager`
- `get_social_router` (if supported)

---

### Admin Functions

Require admin authorization:

- `update_admin`
- `update_registry`
- `update_fee_manager`
- `update_social_router` (if supported)

---

### Governance

- `propose_upgrade`
- `add_voter`
- `remove_voter`
- `cast_vote`
- `apply_upgrade`
- `cancel_proposal`

---

## Security

- Admin-gated configuration updates
- Voter-controlled upgrade approval
- One-time initialization
- Wallet deployment is permissionless

---

## Integration

Used by:

- Wallet contracts
- Identity registry
- Fee manager
- Upgrade module

---

## Notes

- Wallet version is controlled via governance
- Prevent duplicate voters in storage
- Prefer enum over string for proposal types

---

## License

MIT
