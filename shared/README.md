# Shared Package

The **Shared Package** contains common utilities, types, and helpers used across all SocketFi contracts.

It ensures consistency, reduces duplication, and standardizes core logic across the protocol.

---

## Overview

The shared package provides:

- Common data types and enums
- Error definitions
- Utility functions
- Reusable helpers for storage, keys, and tokens

It is imported by all core contracts (Factory, Account, Registry, Router, Fee Manager, Upgrade).

---

## Features

### Common Types

- Shared enums (e.g. upgrade types, statuses)
- Structured data used across contracts
- Standardized interfaces between modules

---

### Error Handling

- Centralized `ContractError` definitions
- Consistent error usage across contracts
- Simplifies debugging and auditing

---

### Utilities

Reusable helpers such as:

- Storage key generators
- Deterministic ID builders (e.g. payment IDs)
- TTL management (e.g. instance bumping)
- Serialization helpers (XDR-based)

---

### Token Helpers

- Safe asset transfer wrappers
- Approval helpers
- Standardized interaction with Soroban token contracts

---

## Usage

Import shared modules in contracts:

```rust
use socketfi_shared::{ContractError, utils::*, tokens::*};
```
