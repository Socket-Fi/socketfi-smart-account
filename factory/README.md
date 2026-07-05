# Factory Contract

The **Factory Contract** is the deployment and governance entry point for SocketFi wallets.

It is responsible for deploying new wallet instances, managing the approved wallet implementation, and coordinating wallet upgrade governance.

---

# Overview

The Factory contract is responsible for:

- Deploying new wallet instances
- Managing the approved wallet WASM version
- Generating wallet creation proof challenges
- Coordinating wallet upgrade governance
- Managing governance voters

---

# Features

## Wallet Deployment

- Permissionless wallet creation
- Passkey proof verification
- Guardian BLS proof verification
- Deterministic wallet creation challenges
- Deploys the currently approved wallet implementation

## Factory Configuration

Stores protocol configuration including:

- Factory administrator
- RP ID hash
- Approved wallet WASM hash

## Upgrade Governance

- Proposal-based wallet upgrades
- Governance voting
- Controlled upgrade execution
- Voter management

---

# Initialization

## `__constructor`

Initializes the factory.

### Parameters

- `admin: Address`
- `rpid: String`
- `wasm: BytesN<32>`

Initialization:

- Stores the factory administrator
- Stores the RP ID hash
- Stores the initial approved wallet WASM hash
- Registers the initial governance voter

---

# Core Functions

## `create_wallet`

Deploys and initializes a new wallet.

### Parameters

- `passkey: BytesN<65>`
- `passkey_sig: PasskeySignature`
- `bls_keys_pop: Vec<BlsKeyWithPoP>`
- `nonce: BytesN<32>`
- `network: Symbol`
- `guardians: Vec<Address>`

### Returns

- `Address`

Before deployment the factory:

- Verifies the wallet creation challenge
- Verifies passkey proof of possession
- Verifies guardian BLS proofs of possession
- Prevents nonce reuse

---

# Read Methods

- `get_wallet_wasm_hash`
- `get_pop_challenge`
- `get_admin`

---

# Administrative Functions

Require factory administrator authorization.

- `update_admin`

---

# Governance

- `propose_upgrade`
- `cast_vote`
- `apply_upgrade`
- `cancel_proposal`
- `add_voter`
- `remove_voter`

---

# Security

- One-time initialization
- Permissionless wallet deployment
- Replay protection through creation nonces
- Passkey proof verification
- Guardian BLS proof verification
- Admin-controlled configuration
- Governance-controlled wallet upgrades

---

# Integration

```
User
   │
   ▼
Factory
   │
   ├── verifies wallet creation proofs
   ├── deploys Wallet
   └── manages wallet upgrade governance
```

---

# Notes

- Wallet deployment is permissionless.
- Wallets are always deployed using the currently approved wallet WASM.
- Wallet creation challenges are deterministic and prevent replay through nonce tracking.
- Wallet version upgrades are controlled through governance.

---

# License

MIT
