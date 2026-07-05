# SocketFi Smart Account Protocol Threat Model

**System:** SocketFi Smart Account Protocol
**Scope:** Factory • Wallet • Shared • Upgrade
**Methodology:** STRIDE
**Purpose:** Security Review • External Audit • Architecture Documentation

---

# 1. Overview

SocketFi is a smart account protocol built on Soroban (Stellar) that provides secure, self-custodial wallets authenticated through passkeys and recoverable through guardian-backed aggregate BLS signatures.

The protocol consists of four primary components:

- Factory
- Wallet
- Shared
- Upgrade

Together they provide permissionless wallet deployment, native Soroban account abstraction, guardian-assisted recovery, and governance-controlled wallet upgrades.

---

# 2. Security Objectives

The protocol is designed to satisfy the following objectives.

## Authentication

Only an authorized wallet owner may execute wallet operations.

## Recovery

Wallet ownership can be securely recovered through the configured bls set without requiring the original passkey.

## Integrity

Wallet state must only be modified through authorized protocol flows.

## Availability

Recovery and emergency pause mechanisms should protect wallets during compromise while minimizing denial-of-service risk.

## Upgrade Safety

Wallet implementation upgrades must only occur through approved governance.

---

# 3. System Components

## Factory

Responsible for:

- Wallet deployment
- Wallet creation challenge generation
- Wallet WASM management
- Governance coordination
- Voter management

---

## Wallet

Responsible for:

- Passkey authentication
- Smart account authorization
- Guardian recovery
- Guardian management
- Emergency pause
- Soroban `CustomAccountInterface`

---

## Shared

Provides:

- Shared data types
- Cryptographic utilities
- Events
- Error definitions
- WebAuthn validation
- BLS utilities

---

## Upgrade

Provides reusable governance utilities including:

- Proposal management
- Voting
- Upgrade execution
- Wallet WASM version management

---

# 4. Critical Assets

The following assets are considered security-sensitive.

## Authentication

- Registered passkey
- RP ID hash
- WebAuthn assertions

## Recovery

- Aggregate guardian BLS public key
- Guardian BLS signatures
- Guardian configuration

## Wallet State

- Wallet assets
- Pause status
- Guardian removal schedule

## Governance

- Wallet WASM hash
- Governance proposal state
- Governance voter set
- Factory administrator

## Deployment

- Wallet creation challenge
- Creation nonce state

---

# 5. Architecture

```
                    User
                     │
                     ▼
                Factory Contract
                     │
          deploys Wallet instance
                     │
                     ▼
               Wallet Contract
          ┌──────────┼──────────┐
          │          │          │
          ▼          ▼          ▼
     Passkeys   Guardians   __check_auth
          │          │
          └──────┬───┘
                 ▼
          Soroban Contract Calls

Factory
    │
    └──── Governance
            │
            ▼
      Wallet WASM Updates
```

---

# 6. Trust Boundaries

| Boundary             | Description             | Primary Risk               |
| -------------------- | ----------------------- | -------------------------- |
| User → Wallet        | WebAuthn authentication | Signature forgery          |
| Guardian → Wallet    | Recovery authorization  | Invalid recovery signature |
| Factory → Wallet     | Wallet deployment       | Malicious deployment       |
| Governance → Factory | Wallet upgrades         | Governance compromise      |
| Wallet → Soroban     | Authenticated execution | Authorization bypass       |

---

# 7. STRIDE Analysis

| Threat                 | ID  | Description                             | Impact                        | Severity |
| ---------------------- | --- | --------------------------------------- | ----------------------------- | -------- |
| Spoofing               | S1  | Forged WebAuthn assertion               | Unauthorized wallet execution | Critical |
| Spoofing               | S2  | Forged aggregate BLS recovery signature | Unauthorized account recovery | Critical |
| Spoofing               | S3  | Unauthorized governance voter           | Malicious upgrades            | Critical |
| Tampering              | T1  | Wallet WASM replacement                 | Protocol compromise           | Critical |
| Tampering              | T2  | Unauthorized guardian modification      | Recovery compromise           | High     |
| Tampering              | T3  | Wallet initialization replay            | Invalid wallet state          | High     |
| Repudiation            | R1  | Missing audit events                    | Reduced forensic capability   | Medium   |
| Information Disclosure | I1  | Exposure of guardian configuration      | Reduced privacy               | Low      |
| Denial of Service      | D1  | Permanent wallet pause                  | Wallet unavailable            | Medium   |
| Denial of Service      | D2  | Guardian removal abuse                  | Recovery disruption           | Medium   |
| Elevation of Privilege | E1  | `__check_auth` bypass                   | Full wallet compromise        | Critical |
| Elevation of Privilege | E2  | Recovery authorization bypass           | Full wallet compromise        | Critical |

---

# 8. Attack Surface

The protocol exposes the following externally accessible operations.

## Factory

- Constructor
- Wallet deployment
- Governance management
- Wallet upgrade proposals
- Governance voting

## Wallet

- Passkey rotation
- Account recovery
- Guardian management
- Pause / unpause
- Smart account authorization

---

# 9. Security Mitigations

## Authentication

Mitigations include:

- WebAuthn assertion verification
- RP ID validation
- Challenge binding
- Proof-of-possession verification
- Authorization context validation

---

## Recovery

Mitigations include:

- Aggregate BLS signature verification
- Guardian proof-of-possession
- Configurable guardian limits
- Duplicate guardian rejection

---

## Deployment

Mitigations include:

- Deterministic wallet creation challenges
- Nonce replay protection
- One-time initialization

---

## Governance

Mitigations include:

- Proposal-based upgrades
- Governance voting
- Controlled upgrade execution
- Approved wallet WASM hashes

---

## Emergency Controls

Mitigations include:

- Guardian-triggered pause
- Guardian-approved unpause
- Delayed guardian removal

---

# 10. Security Invariants

The protocol maintains the following invariants.

- Wallet initialization occurs exactly once.
- Every wallet has exactly one registered passkey.
- Wallet execution requires successful `__check_auth`.
- Recovery requires a valid aggregate guardian BLS signature.
- Wallet creation challenges cannot be replayed.
- Duplicate guardians cannot exist.
- Guardian count never exceeds protocol limits.
- Paused wallets cannot execute arbitrary operations.
- Wallet upgrades require governance approval.
- New wallets are deployed only from the currently approved wallet WASM.

---

# 11. Example Attack Scenarios

## Forged Passkey

An attacker attempts to submit a fabricated WebAuthn assertion.

Mitigation:

- Challenge validation
- RP ID validation
- P-256 signature verification

---

## Recovery Attack

An attacker attempts to recover a wallet without guardian authorization.

Mitigation:

- Aggregate BLS signature verification
- Stored aggregate public key verification

---

## Replay Attack

An attacker attempts to reuse a previous wallet creation challenge.

Mitigation:

- Deterministic challenge generation
- Nonce tracking
- Nonce invalidation after deployment

---

## Governance Compromise

A malicious proposal attempts to deploy unauthorized wallet code.

Mitigation:

- Governance voting
- Controlled execution
- Approved WASM tracking

---

## Guardian Abuse

A malicious guardian attempts to permanently prevent wallet use.

Mitigation:

- Separate pause and unpause rules
- Delayed guardian removal
- Wallet owner authentication for guardian management

---

# 12. Assumptions

The protocol assumes:

- Soroban correctly enforces `CustomAccountInterface`.
- WebAuthn implementations correctly generate assertions.
- BLS12-381 cryptography remains secure.
- Governance keys remain secure.
- Factory deploys audited wallet implementations.
- Soroban host execution is deterministic.

---

# 13. Out of Scope

The following are outside the scope of this document.

- Frontend security
- Browser passkey implementations
- Operating system security
- Hardware authenticator security
- Soroban runtime security
- Stellar consensus security

---

# 14. Residual Risk

Residual risks include:

- Compromise of governance keys
- Compromise of a sufficient guardian quorum
- WebAuthn implementation vulnerabilities
- Cryptographic weaknesses in future standards
- Human operational error

---

# 15. Design Principles

- Passkey-first authentication
- Self-custodial wallet ownership
- Defense in depth
- Least privilege
- Explicit authorization
- Deterministic execution
- Modular architecture
- Upgrade safety
- Secure recovery

---

# 16. Workspace

```text
/
├── factory
├── wallet
├── shared
├── upgrade
└── docs
    └── security
        └── threat-model.md
```

---

# 17. Conclusion

SocketFi's security model is centered around Soroban's native smart account architecture, combining WebAuthn passkey authentication, guardian-assisted recovery through aggregate BLS signatures, deterministic wallet deployment, and governance-controlled upgrades.

By minimizing trust assumptions, validating all authentication paths, and separating deployment, execution, recovery, and governance responsibilities, the protocol provides a modular and defense-in-depth architecture suitable for production deployments and independent security review.
