# V3 account-creation proofs

This is a coordinated account, factory, API, and SDK release. V3 proofs are not
compatible with an older factory or client.

- `create_account(..., guardians, live_until_ledger)` keeps the signed expiry as
  its final argument.
- `get_pop_challenge` receives the proposed Passkey, Stellar, or EVM commitment,
  ordered BLS public keys, nonce, network, guardians, and expiry.
- The SHA-256 domain is `SOCKETFI_CREATE_ACCOUNT_POP_V3`.
- The preimage commits to the actual ledger network ID, factory address, declared
  network, trusted RP-ID hash, approved account WASM, selected owner commitment,
  ordered BLS keys, ordered guardians, nonce, and expiry.
- Validity is inclusive: `current <= expiry <= current + 120`, also bounded by
  the available temporary-storage TTL.
- A successful deployment writes a temporary nonce tombstone through expiry and
  a keyed persistent canonical-account registry entry. Failed creation rolls back
  both deployment and storage writes.
- Legacy persistent nonce tombstones remain honored.

## Release order

1. Update API and SDK encoders for the V3 factory constructor, creation challenge,
   Stellar proof of possession, and targeted binding methods.
2. Run formatting, strict Clippy, unit tests, release-WASM lifecycle tests, and
   the reproducible release workflow for the exact reviewed commit.
3. Deploy a new TESTNET factory with explicit TESTNET network configuration,
   initial account and factory WASM hashes, and at least three unique voters
   including the administrator.
4. Update TESTNET API and indexer factory IDs and complete physical-device tests
   for Passkey, Stellar, and EVM creation plus every binding-management path.
5. Obtain an external security review before a PUBLIC deployment. Deploy PUBLIC
   separately and never reuse challenges, configuration, or state across networks.

No deployment or checked-in WASM replacement is performed by the source change.
