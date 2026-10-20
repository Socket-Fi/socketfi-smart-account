# Multi-binding account authorization

This document defines the authorization model introduced by the multi-binding
account release. It is part of the contract interface and must remain aligned
with the account, factory, API, and SDK implementations.

## Binding slots

Each account has three independent optional owner-binding slots:

| Slot | Stored commitment | Transaction proof |
| --- | --- | --- |
| Passkey | uncompressed P-256 public key | WebAuthn assertion with RP-ID, UV, UP, challenge, and P-256 signature checks |
| Stellar | Ed25519 public key | Ed25519 signature |
| EVM | 20-byte address | canonical low-s secp256k1 `personal_sign` signature |

An account is created with exactly one slot populated. It may later contain one,
two, or all three slots, but never more than one binding of a type and never zero
bindings. Every populated slot can authorize normal account operations through
`__check_auth`.

## Binding-management matrix

| Operation | Existing authorization | Candidate proof | Effect |
| --- | --- | --- | --- |
| `add_binding` | every currently populated slot | required | fills one empty slot |
| `rotate_binding` | the slot being rotated | required, same type | replaces only that slot |
| `remove_binding` | the slot being removed | none | removes only that slot; another must remain |
| `recover_binding_with_bindings` | the other two slots | required, same target type | replaces one inaccessible slot; available only when all three slots exist |
| `recover_binding_bls` | aggregate BLS recovery signature | required, same target type | replaces one slot |

One binding can never rotate, remove, or recover another binding by itself.
BLS recovery cannot clear the account or replace all bindings. Guardian addresses
remain limited to pause and unpause coordination and are not recovery signers.

While the account is paused, addition, rotation, removal, migration, normal owner
execution, and sessions fail closed. Targeted peer and BLS recovery remain
available so a compromised binding can be replaced before guardian-approved,
owner-authenticated unpause.

Adding a second binding therefore needs one current approval. Adding a third
needs both current approvals. Peer recovery is deliberately unavailable with only
one or two bindings because there are not two independent remaining owner slots.

## Replay and domain separation

Every management challenge commits to:

- a distinct operation domain;
- the ledger network ID;
- the account contract address;
- the target binding type;
- the current commitment, when applicable;
- the replacement commitment, when applicable;
- the account authentication-configuration nonce; and
- an expiry ledger no more than 60 ledgers in the future.

Commitments are encoded as `type_byte || raw_key`, then SHA-256 hashed. The
management preimage uses fixed-width fields:

```text
domain
|| network_id[32]
|| account_address_xdr
|| target_type[1]                 # passkey=0, stellar=1, evm=2
|| current_present[1]
|| current_commitment_hash[32]    # zeroes when absent
|| replacement_present[1]
|| replacement_commitment_hash[32]
|| auth_config_nonce_u64_be[8]
|| live_until_ledger_u32_be[4]
```

Clients must use the SDK implementation of this encoding. The contract recomputes
the challenge and verifies every submitted signature. A successful binding change
increments the configuration nonce, making its signatures unusable again.

## Sessions and migration

Adding a binding preserves existing sessions because all existing owners approved
the addition and no prior owner was removed. Rotation, removal, peer recovery,
BLS recovery, and migration increment the global session epoch, immediately
invalidating sessions issued under the previous authority configuration.

Migration requires explicit approval from every currently populated binding. The
migration challenge commits to the network, account, approved target WASM,
configuration nonce, and expiry. A successful migration records the installed
WASM, consumes the configuration nonce, invalidates sessions, and then updates
the contract atomically.

## Factory creation

The factory still creates an account with exactly one initial owner binding. Its
V3 creation challenge commits to the actual ledger network, factory address,
declared network, RP-ID hash, approved account WASM, selected owner commitment,
ordered BLS keys, ordered guardian list, nonce, and expiry. The factory enforces
its configured TESTNET or PUBLIC network and writes a keyed canonical registry
entry only after successful deployment.

Factory and account artifacts are a coordinated release. Existing clients using
`rotate_account` or `recover_account` must migrate to the targeted binding APIs.
`StellarAccountSigner` now includes an Ed25519 proof-of-possession signature.

## Governance

Factory initialization requires at least three unique voters and the administrator
must be one of them. Administrator replacement, proposal cancellation, and voter
set changes require both administrator authorization and the current 75 percent
voter threshold. Applied WASM hashes cannot be proposed again. Proposal voters and
thresholds are snapshotted, and voting closes exactly at the deadline.

## Operational requirements

- Release the account and factory together and update every SDK/API encoder first.
- Do not point old clients at the new factory ABI.
- Keep TESTNET and PUBLIC deployments, contract IDs, and signed payloads separate.
- Run the native unit suite, strict Clippy, release-WASM build, and ignored WASM
  lifecycle suite before producing release attestations.
- Run an external contract security review before a PUBLIC deployment.
- Maintain a TTL keeper/restoration procedure for factory registry and governance
  persistent entries; reads refresh TTL but inactive entries may archive.
