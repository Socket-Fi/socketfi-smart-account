# Expiring account-creation proofs

This is a coordinated factory/API release, not an account migration.
V1/V2 below refer only to internal proof formats, not contract product names. Do not
point a V1 API at this factory or a V2 API at the previous factory.

- `get_pop_challenge(nonce, network, live_until_ledger)` adds a final u32.
- `create_account(..., guardians, live_until_ledger)` adds the same final u32.
- The SHA-256 domain is `SOCKETFI_CREATE_ACCOUNT_POP_V2`, followed by ScVal XDR
  of actual network ID, factory address, network symbol, RP hash, nonce, expiry.
- Validity is inclusive: current <= expiry <= current + 120, also bounded by
  available storage TTL. No timestamp-to-ledger conversion is authoritative.
- Expired proofs return 502; excessive expiry returns 503; consumed nonces
  retain error 501. Existing error values and creation event fields are unchanged.
- New nonce records use temporary storage and extend TTL through expiry. Network
  minimum TTL can retain them longer. Failed creations roll back all changes.
- Persistent legacy tombstones remain honored. Do not delete them, accept V1
  signatures on V2, or add a fallback after failed V2 simulation.

## Deployment order

1. Commit/review the factory and API changes. Run the verified release workflow
   for that exact contract commit; verify attestations and use its exact WASMs.
   Local `target/` WASMs are test builds, not the canonical Linux release.
2. Upload matching account/factory artifacts and deploy a new Testnet factory
   with the chosen admin and `socket.fi` RP ID. No deployment is part of this edit.
3. In `socketfi-sdk/apps/api/soroban/contracts.js`, replace the TESTNET
   `MASTER_CONTRACT` with the new factory ID and retain `CREATION_PROOF_VERSION: 2`.
   The currently recorded CDKPBQ5... factory is V1 and must be replaced before
   restarting this staged API. PUBLIC remains configured for V1.
4. Rebuild/restart the API. Restart unfinished signup flows to obtain fresh
   proofs; old sessions/cookies are not valid across a factory/version change.
5. Verify all three signup methods and expiry/retry handling on Testnet.
   Existing accounts, login tokens, account authorization, and events do not migrate.

REST request/response shapes stay unchanged. The API keeps factory/network,
version, and exact expiry in the existing server session/native context or
passkey creation cookie, and supplies it during contract submission. BLS nodes
still sign opaque challenge bytes. App/SDK clients do not reconstruct that hash.
Indexer event parsers require no change; any deployment-specific factory discovery
configuration must be updated separately for the new factory.

The older RP-ID release guide documents its original release; V2 supersedes its
statement that factory creation inputs are unchanged. No other repository's
checked-in WASM is replaced.
