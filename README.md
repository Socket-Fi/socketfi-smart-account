# SocketFi

**SocketFi** is a modular smart account infrastructure built on Soroban (Stellar), enabling embedded self-custody through passkeys, social authentication, account abstraction, and programmable transaction execution.

---

# Overview

SocketFi provides a production-ready smart contract system for:

- Smart account deployment
- Passkey-based authentication
- Programmable transaction execution
- Upgradeable protocol architecture
- Shared libraries for reusable logic

The protocol is designed around a modular architecture where each contract has a well-defined responsibility while remaining composable with the rest of the system.

---

# Architecture

The current workspace consists of the following packages.

## Core Contracts

### Factory

Responsible for:

- Deploying new smart accounts
- Initializing wallet configuration
- Managing protocol-wide deployment logic

### Wallet

The primary smart account implementation providing:

- Passkey authentication
- Transaction execution
- Multi-operation support
- Asset management
- Authorization validation
- Extensible account abstraction

---

## Shared Libraries

### Shared

Common protocol functionality including:

- Shared types
- Utility functions
- Authentication helpers
- Token helpers
- Serialization helpers
- Common interfaces

### Upgrade

Provides reusable governance upgrade utilities including:

- Upgrade authorization
- Contract migration helpers
- Version management
- Safe upgrade patterns

---

# Contract Relationships

```
Factory
    │
    └──── deploys ─────► Wallet
                              │
                              │ uses
                              ▼
                           Shared

Factory ───────────────► Upgrade

Wallet ────────────────► Upgrade
Wallet ────────────────► Shared
Factory ───────────────► Shared
```

---

# Key Features

## Smart Accounts

- Passkey-native authentication
- Self-custodial architecture
- Secure transaction execution
- Flexible authorization model
- Soroban-native account abstraction

## Wallet Deployment

- Permissionless wallet creation
- Deterministic deployment
- Factory-managed initialization

## Authentication

- Passkey support
- Signature verification
- Extensible authentication framework

## Upgradeability

- Governance-compatible upgrade utilities
- Safe migration support
- Versioned contracts

## Shared Infrastructure

- Reusable utilities
- Shared protocol types
- Consistent interfaces
- Reduced code duplication

---

# Workspace Structure

```
/factory
/wallet
/shared
/upgrade
```

---

# Development

## Requirements

- Rust (stable)
- Soroban SDK
- Cargo

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test
```

---

# Design Principles

- **Modularity** — Each package has a single responsibility.
- **Security First** — Authentication and validation are enforced throughout the protocol.
- **Composability** — Components are designed to work together while remaining independently reusable.
- **Determinism** — Smart account behavior is predictable and reproducible.
- **Maintainability** — Shared libraries reduce duplication and simplify future development.

---

# Typical Flow

1. A user requests a new smart account.
2. The Factory deploys and initializes a Wallet.
3. The Wallet authenticates the user using a passkey.
4. The Wallet validates authorization.
5. The requested transaction is executed.
6. Future protocol upgrades are managed through the Upgrade library.

---

# Repository Structure

```
socketfi/
├── factory/
├── wallet/
├── shared/
├── upgrade/
└── README.md
```

---

# Notes

- Wallet deployment is permissionless.
- Authentication is built around passkeys.
- Contracts share reusable logic through the Shared package.
- Upgrade functionality is isolated to simplify governance and maintenance.

---

# License

MIT
