# SocketFi Factory Contract

The **Factory Contract** is the deployment, registry, configuration, and implementation-governance entry point for SocketFi smart accounts on Soroban.

It permissionlessly deploys new Account instances from the currently approved Account WASM, verifies account-creation proofs, prevents creation-request replay, records canonical SocketFi accounts, and coordinates approval of future Account implementations.

---

## Overview

The Factory is responsible for:

- Deploying and initializing SocketFi Account contracts
- Generating deterministic account-creation challenges
- Verifying owner proof of possession during account creation
- Verifying guardian BLS proofs of possession
- Preventing creation nonce reuse
- Recording deployed Accounts in the canonical registry
- Storing protocol-wide Account configuration
- Managing the approved Account WASM and version
- Coordinating implementation governance and voter membership

The Factory does not hold user assets and should not be able to execute ordinary Account operations.

---

## Architecture

```text
User or Integrator
        |
        | account configuration + proofs + nonce
        v
Factory Contract
        |
        | verifies proofs and consumes nonce
        | deploys approved Account WASM
        | records canonical Account
        v
Account Contract
        |
        | owner/session-authorized execution
        v
Soroban Applications
```

For upgrades:

```text
Governance approves implementation
                |
                v
Factory publishes WASM hash and version
                |
                v
Account owner authorizes migration
                |
                v
Account updates its own WASM
```

The Factory determines which implementation is officially approved. Existing Accounts should retain control over whether to adopt that implementation unless an Account owner has explicitly enabled a separately documented automatic-upgrade policy.

---

## Features

### Permissionless Account Deployment

- Any caller may submit a valid Account creation request
- Deployment uses the currently approved Account WASM
- Account initialization is performed atomically with deployment
- A failed initialization does not leave a usable partially initialized Account
- Successful deployments are recorded in the Factory registry

### Multi-Authentication Creation Proofs

Depending on the enabled Account configuration, creation may support:

- WebAuthn passkey proof of possession using P-256
- Stellar Ed25519 signer proof of possession
- EVM secp256k1 signer proof of possession
- Guardian BLS public-key proofs of possession

The Factory must validate the selected authentication configuration and reject missing, conflicting, malformed, or unsupported combinations.

### Replay Protection

- Every creation request includes a unique `BytesN<32>` nonce
- The nonce is bound into the creation challenge
- A nonce is consumed only by a successful creation transaction
- A consumed nonce cannot be reused
- Challenges are domain-separated from rotation, recovery, session, and transaction signatures

### Canonical Account Registry

The Factory records Accounts it successfully deployed. Integrations can verify both:

```text
account.factory() == official_factory
AND
official_factory.is_registered_account(account) == true
```

An Account merely storing the official Factory address is not sufficient proof of canonical deployment, because independently deployed code could be initialized with that same address.

### Implementation Governance

- Proposals identify a candidate Account WASM hash and version
- Eligible voters cast one vote per proposal
- Approved proposals may be applied only after satisfying governance rules
- Proposal cancellation follows explicit authorization and state-transition rules
- Applied versions must advance monotonically
- New Accounts use the latest approved implementation
- Existing Accounts adopt approved migrations through their own authorization flow

---

## Initialization

### `__constructor`

Initializes the Factory exactly once.

Typical parameters:

- `admin: Address`
- `rpid: String`
- `wasm: BytesN<32>`

Initialization:

- Requires and stores the Factory administrator
- Validates the relying-party identifier
- Derives and stores the RP ID hash
- Stores the initial approved Account WASM hash
- Initializes the approved Account version
- Registers the initial governance voter
- Initializes governance and replay-protection state

The deployed WASM hash must refer to uploaded Soroban contract code compatible with the Account constructor expected by this Factory version.

---

## Account Creation

### `create_account`

Deploys and initializes a new SocketFi Account.

The exact parameters depend on the enabled owner-authentication configuration. A passkey-based creation flow commonly includes:

- `passkey: BytesN<65>`
- `passkey_sig: PasskeySignature`
- `bls_keys_pop: Vec<BlsKeyWithPoP>`
- `nonce: BytesN<32>`
- `network: Symbol`
- `guardians: Vec<Address>`
- `live_until_ledger: u32` (V2: final argument, signed expiry)

Multi-auth versions may additionally accept an optional Stellar signer, an optional EVM signer, and the corresponding proof of possession.

Returns:

- `Address` — the deployed Account contract address

Before deployment, the Factory:

1. Validates the network, creation input, and signed expiry (at most 120 ledgers ahead).
2. Rejects an already consumed nonce.
3. Constructs the domain-separated creation challenge.
4. Verifies the selected owner credential’s proof of possession.
5. Verifies guardian BLS proofs and rejects rogue or duplicate keys.
6. Validates guardian addresses, limits, and uniqueness.
7. Deploys the approved Account WASM.
8. Initializes the Account with its immutable Factory reference.
9. Marks the nonce as consumed in temporary storage through the expiry ledger.
10. Emits an account-created event.

All state changes occur in one Soroban transaction and are atomic.

---

## Creation Challenge

### `get_pop_challenge`

Returns the deterministic challenge that must be signed to prove control of the proposed owner credential and guardian keys.

V2 takes `(nonce, network, live_until_ledger)`. Its exact SHA-256 preimage is:

```text
raw("SOCKETFI_CREATE_ACCOUNT_POP_V2")
|| XDR(actual ledger network ID)
|| XDR(factory address)
|| XDR(network symbol)
|| XDR(RP ID hash)
|| XDR(nonce)
|| XDR(live_until_ledger)
```

All XDR components are Soroban ScVals. The expiry is inclusive and must be no
more than 120 ledgers ahead of the current ledger. The same expiry is the final
argument to `create_account`. Changing it invalidates the owner/BLS proofs.
Temporary replay records remain live through that ledger, then may be deleted;
the expired proof is rejected even when its nonce entry is gone. Existing legacy
persistent nonce records are still checked and are not deleted by this change.

The challenge does not serialize the complete owner/guardian configuration.
Existing signer proof-of-possession and guardian/BLS validation still apply;
this expiry change is not a full creation-configuration commitment redesign.

See [the rollout guide](../docs/creation-proof-expiry.md).

---

## Read Methods

### `get_latest_account_wasm`

Returns the currently approved Account WASM hash.

### `get_latest_account_version`

Returns the monotonically increasing version associated with the approved Account implementation.

### `get_pop_challenge`

Returns the creation proof challenge for the supplied Account configuration.

### `get_admin`

Returns the current Factory administrator.

### `get_rpid_hash`

Returns the configured WebAuthn RP ID hash.

### `is_registered_account`

Returns whether an address was canonically deployed and recorded by this Factory.

### `is_nonce_used`

Returns whether a creation nonce has already been consumed.

Read-method names should match the deployed contract interface. If the implementation currently exposes `get_wallet_wasm_hash`, retain that method temporarily as a compatibility alias while clients migrate to Account terminology.

---

## Administration

Administrative functions require authorization from the stored Factory administrator.

### `update_admin`

Transfers Factory administration to a new address.

Recommended controls:

- Require current-admin authorization
- Reject invalid or unchanged addresses
- Prefer a two-step transfer for production deployments
- Emit an admin-updated event

The administrator may manage operational configuration, but should not bypass implementation-governance voting or authorize user Account operations.

---

## Upgrade Governance

### `propose_upgrade`

Creates a proposal for a new Account WASM hash and version.

The proposal should contain:

- Proposal identifier
- Candidate WASM hash
- Candidate version
- Proposer
- Creation and expiration ledgers
- Vote counts or voter decisions
- Current proposal status

### `cast_vote`

Records an eligible voter’s decision.

The Factory must reject:

- Votes from unauthorized addresses
- Duplicate votes by the same voter
- Votes on inactive, cancelled, expired, or applied proposals

### `apply_upgrade`

Marks an approved WASM hash and version as the latest Account implementation after the proposal satisfies the configured threshold and timing rules.

Applying a proposal:

- Changes the implementation used for future Account deployments
- Makes the implementation available for owner-authorized Account migration
- Does not by itself authorize ordinary operations on existing Accounts
- Does not silently migrate existing Accounts

### `cancel_proposal`

Cancels an eligible active proposal according to the governance authorization rules.

### `add_voter`

Adds a governance voter with the required administrative or governance authorization.

### `remove_voter`

Removes an existing voter while preserving a valid governance configuration.

The implementation should prevent removal from making the configured approval threshold impossible to satisfy.

---

## Events

The Factory should emit indexable events for:

- `account_created`
- `account_registered`
- `admin_updated`
- `upgrade_proposed`
- `vote_cast`
- `upgrade_applied`
- `proposal_cancelled`
- `voter_added`
- `voter_removed`

An `account_created` event should include at least:

- Account address
- Factory address
- Account WASM hash
- Account version
- Creation nonce or its hash
- Owner authentication type
- Creation ledger

Events support discovery, history, and analytics. Contract storage remains authoritative for authorization and replay protection.

---

## Storage Model

Typical Factory state includes:

### Instance Storage

- Administrator
- RP ID hash
- Latest Account WASM hash
- Latest Account version
- Governance configuration
- Voter set, if strictly bounded

### Persistent Storage

- Used creation nonces
- Registered Account addresses
- Upgrade proposals
- Per-proposal votes
- Other independently expiring or unbounded records

Every persistent entry required beyond its current live range must have its TTL extended. Instance TTL must also be bumped from public entry points according to the protocol’s archival policy.

Do not store unbounded Account registries or proposal histories as one growing instance-storage vector. Use keyed records and discoverable events.

---

## Security Model

### Creation Proof Binding

Proofs must be bound to the complete Account configuration. Omitting a signer, guardian set, Factory address, network, or nonce from the challenge may allow substitution or cross-deployment replay.

### Nonce Consumption

Nonce state must be checked before deployment and committed atomically with successful creation. A failed transaction must not permanently consume the nonce.

### Authentication Separation

Use distinct domains for:

- Account creation
- Passkey or signer rotation
- Account recovery
- Session creation
- Transaction authorization
- Migration approval

A signature valid for one operation must never be accepted for another.

### Guardian BLS Proofs

Each BLS key must provide proof of possession before aggregation. The Factory must reject duplicate keys and malformed points to prevent rogue-key attacks.

### Implementation Approval

Governance approval means that an implementation is recognized by SocketFi. It must not be treated as Factory authority over user funds. Existing Accounts should require owner authentication before updating their own WASM.

### Registry Integrity

Only the Account deployment path may write canonical registry entries. Registration must not be exposed as a general administrator-controlled method without cryptographic proof of Factory deployment.

### Authorization

- Permissionless creation does not mean unverified creation
- Administrative functions require administrator authorization
- Governance actions require their configured voter or governance authorization
- Existing Account execution remains subject to that Account’s `__check_auth`

---

## Security Invariants

The Factory must maintain the following invariants:

1. Factory initialization occurs exactly once.
2. Every successful Account deployment uses the approved WASM active during that transaction.
3. Every created Account is initialized atomically.
4. Every canonical registry entry corresponds to an Account deployed by this Factory.
5. Every created Account stores the correct immutable Factory address.
6. A consumed creation nonce cannot be reused.
7. Creation proofs are bound to the complete authority configuration.
8. Proof domains cannot be reused across operation types or networks.
9. Every accepted owner credential has a valid proof of possession.
10. Every aggregated BLS key is derived only from validated proofs of possession.
11. Duplicate guardians and duplicate BLS keys are rejected.
12. Only eligible voters can vote.
13. A voter can vote at most once per proposal.
14. An upgrade can be applied only once and only after approval.
15. Approved Account versions increase monotonically.
16. A Factory governance decision cannot directly authorize ordinary Account execution.
17. Existing Accounts are not silently migrated unless their documented authorization model explicitly permits it.

---

## Integration Flow

1. The client selects an owner authentication type.
2. The client generates a unique creation nonce.
3. The client requests or locally reproduces the Factory challenge.
4. The owner credential signs its proof of possession.
5. Guardian BLS keys sign their proofs of possession.
6. The client submits `create_account`.
7. The Factory verifies the request and deploys the Account.
8. The Factory records and emits the canonical Account address.
9. The client confirms the returned address and registry status.

Clients should derive the challenge from the exact Factory version they call and should never sign an opaque payload without displaying the intended network and action.

---

## Testing Priorities

Tests should cover:

- Constructor reinitialization rejection
- Successful creation for every supported owner-authentication type
- Invalid and conflicting signer configurations
- Invalid passkey, Stellar, EVM, and BLS proofs
- Cross-domain and cross-network replay attempts
- Nonce reuse before and after successful deployment
- Failed deployment rollback and nonce availability
- Duplicate guardians and duplicate BLS keys
- Registry correctness and forged-registration attempts
- Deployment using the latest approved WASM
- Governance authorization and duplicate voting
- Proposal expiration, cancellation, and repeated application
- Version rollback rejection
- Voter-threshold edge cases
- TTL extension and archived-entry behavior
- Owner-authorized migration integration

---

## Design Principles

- Permissionless deployment with verified initialization
- Self-custodial Account ownership
- Explicit and domain-separated authorization
- Replay-resistant creation
- Canonical deployment provenance
- Governance-approved implementations
- Owner-controlled migration
- Bounded on-chain state
- Event-driven indexing
- Soroban-native account abstraction

---

## Notes

- Use **Account** rather than **Wallet** in new internal interfaces, storage keys, events, documentation, and filenames.
- Preserve legacy method names only where temporary compatibility is required.
- The approved WASM must already be uploaded to Soroban before it can be deployed or adopted.
- Account constructor changes must be coordinated with the Factory deployment interface and versioning strategy.
- Governance should be protected by a multisig and, where practical, a timelock.
- Factory registry checks establish canonical SocketFi provenance; they do not replace Account authorization.

---

## License

MIT


### RP configuration deployment compatibility

Creation always passes `Some(factory_rpid_hash)` to the account constructor,
including EVM and Stellar ownership. The hash remains factory-controlled and
the RP configuration itself adds no account-constructor argument. V2 separately
adds a signed expiry to the factory creation inputs. Missing factory RP configuration
fails closed. Signer selection and Stellar authorization are unchanged.

The matching account implementation must accept RP configuration independently
of passkey presence. Roll out the factory logic and matching account WASM as a
coordinated release; mixed old/new versions reject non-passkey creation. Do not
resume creation until both versions are active. Existing accounts are unaffected.
