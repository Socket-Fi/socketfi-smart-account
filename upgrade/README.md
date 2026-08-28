# Upgrade Contract

The **Upgrade Contract** manages governance-driven upgrades for core contracts within the SocketFi ecosystem.

It enables secure proposal, voting, and execution of contract upgrades (e.g. account versions) using a controlled multi-voter mechanism.

---

## Overview

The Upgrade contract is responsible for:

- Managing upgrade proposals
- Coordinating validator/voter approvals
- Enforcing upgrade thresholds
- Applying approved upgrades

---

## Features

### Proposal System

- Create upgrade proposals with a target WASM hash
- Supports multiple upgrade types (e.g. account, protocol)
- Ensures only one active proposal at a time

### Voting

- Approved voters can participate
- Enforces unique voter participation
- Requires threshold-based approval

### Upgrade Execution

- Applies upgrade after successful voting
- Updates stored contract version/state
- Clears proposal state after execution

---

## Core Functions

### `propose_upgrade`

Creates a new upgrade proposal.

**Params:**

- `proposal_type: String`
- `new_wasm_hash: BytesN<32>`

---

### `cast_vote`

Casts a vote for an upgrade proposal.

**Params:**

- `voter: Address`
- `wasm_hash: BytesN<32>`

---

### `apply_upgrade`

Executes the approved upgrade.

**Returns:**

- `BytesN<32>` — applied WASM hash

---

### `cancel_proposal`

Cancels the active proposal.

---

## Data Model

### Proposal

- `proposal_type`
- `new_wasm_hash`
- `voters`
- `votes`
- `deadline` (if implemented)

### Storage

- Active proposal state
- Voter list
- Vote tracking

---

## Integration

Works with:

- Factory Contract → applies account upgrades
- Account Contract → receives updated WASM version
- Governance system → manages voter set

---

## Security

- Admin-controlled proposal creation
- Voter authorization required
- Duplicate votes prevented
- Threshold enforcement before execution
- Single active proposal at a time

---

## Notes

- Proposal types are string-based (enum recommended for stricter validation)
- Ensure proper deadline handling (if enabled)
- Upgrade execution must only occur after quorum is reached

---

## License

MIT
