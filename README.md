# SocketFi

**SocketFi** is a modular smart wallet ecosystem built on Soroban (Stellar), enabling seamless Web3 interactions through social identity, passkeys, and flexible fee abstraction.

---

## Overview

SocketFi provides a full-stack smart contract system for:

- Smart wallet deployment and execution
- Social identity-based payments
- Flexible fee handling (including deferred fees)
- Governance-driven upgrades
- Shared utilities for consistent contract design

The architecture is designed to be modular, composable, and production-ready.

---

## Architecture

The protocol consists of the following core packages:

### Core Contracts

- **Factory** → Deploys wallets and manages system configuration
- **Wallet** → Smart wallet for asset management and execution
- **Identity Registry** → Maps social identities to wallet addresses
- **Social Payment Router** → Enables payments via user identifiers
- **Fee Manager** → Handles fee calculation and settlement

---

### Shared Packages

- **Shared** → Common types, utilities, and token helpers
- **Access** → Admin and dependency access control helpers
- **Upgrade** → Manages governance-driven upgrades

---

## Contract Relationships

Factory → deploys → Wallet

Wallet → uses → Fee Manager  
Wallet → uses → Identity Registry

Router → resolves → Identity Registry  
Router → routes → Wallet

Factory → integrates → Upgrade  
All contracts → use → Shared + Access

---

## Key Features

- **Smart Wallets**

  - Passkey-based authentication
  - Optional BLS multi-signature support

- **Social Payments**

  - Send assets using `(platform, user_id)`
  - Automatic wallet resolution via registry

- **Fee Abstraction**

  - Pay fees in supported assets
  - Support for deferred fee settlement

- **Governance**

  - Proposal-based upgrades
  - Multi-voter approval system

- **Modular Design**
  - Contracts are loosely coupled
  - Reusable shared logic across modules

---

## Workspace Structure

/factory
/wallet
/identity_registry
/social_router
/fee_manager
/upgrade
/shared
/access

---

## Development

### Requirements

- Rust (stable)
- Soroban SDK

### Build

cargo build --release

### Test

cargo test

---

## Design Principles

- **Modularity** → Each contract has a single responsibility
- **Security-first** → Strict auth and validation patterns
- **Determinism** → Predictable behavior across contracts
- **Composability** → Contracts interact cleanly via interfaces

---

## Integration Flow (Example)

1. User creates wallet via Factory
2. Identity is linked in Registry
3. Payment is initiated via Router
4. Router resolves recipient wallet
5. Wallet executes transfer
6. Fee Manager applies fee logic

---

## Notes

- Wallet deployment is permissionless
- Identity resolution depends on registry state
- Fee logic supports both immediate and deferred models
- Upgrade system controls contract evolution

---

## License

MIT
