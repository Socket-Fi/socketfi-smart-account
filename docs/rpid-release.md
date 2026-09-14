# RP-ID initialization release

## Behavior

Every newly created account receives and persists the factory's RP-ID hash,
including accounts initially owned by an EVM or Stellar signer. A passkey is
installed only when a complete passkey configuration and valid proof are supplied.
This allows a later owner-authorized rotation to a passkey using the account's
original RP configuration. Signer clearing preserves that configuration.

The account constructor still encodes the RP-ID argument as an option, but now
requires `Some(hash)`. Factory `create_account` inputs, events, storage keys,
error discriminants, signing challenges, and account addresses are unchanged by
this source change. A different approved WASM can affect deployment behavior;
validate the complete creation flow against the intended factory before release.
No new API environment variable or database migration is introduced here.

## Build provenance

- Rust: 1.91.0 (`rust-toolchain.toml`).
- Soroban SDK: 25.3.1 (workspace manifest).
- Dependencies: root `Cargo.lock`; all release commands use `--locked`.
- Target: `wasm32v1-none`.
- Profile: root `[profile.release]`; no external WASM optimizer is applied.
- Contracts: `socketfi-account` and `socketfi-factory` from the same source tree.

```bash
make build
make test
make test-wasm
make fmt-check
make lint
shasum -a 256 target/wasm32v1-none/release/socketfi_account.wasm \
  target/wasm32v1-none/release/socketfi_factory.wasm
```

Record the eventual source commit, toolchain, lockfile hash, build command, and
both artifact hashes with the release. Local artifacts are ignored by Git and
must not be substituted into another repository's public WASM directory as a
side effect. Rebuild after any contract source or dependency change.

## Validation scope

Unit tests cover RP-ID persistence for EVM, Stellar, and passkey creation,
missing RP configuration, incomplete passkey configuration, invalid EVM proof,
wrong RP-ID proof, and factory enforcement of its own RP configuration.

The WASM lifecycle test creates an EVM-owned account through the compiled factory,
using the compiled account and real synthetic BLS/EVM proofs. It verifies that
wrong-RP passkey rotation and an unauthorized EVM owner fail, that the legitimate
owner can rotate to a passkey, that rotation advances the session epoch, that
replay and the removed EVM signer fail, and that the new passkey can authorize an
account operation. No authorization mocking is used in that integration test.

These focused regressions are not a comprehensive independent contract audit.
The access, shared, and upgrade packages do not yet have their own unit suites.
Live network compatibility, paymaster/API integration, browser/native WebAuthn,
and deployed contract state require separate validation before production release.

## Coordinated activation — not performed by local checks

Do not activate only one half of this change:

- Old factory + new account: EVM/Stellar creation sends no RP ID and is rejected.
- New factory + old account: EVM/Stellar creation supplies an RP ID that the old
  constructor treats as an incomplete passkey configuration.

Prepare a coordinated factory implementation and approved-account-WASM update.
Inspect the target network's governance/upgrade mechanism before deciding how to
activate them; do not assume separate transactions are atomic. If activation is
not atomic, prevent account creation through mismatched implementations for the
whole transition window, including direct factory callers. A backend-only pause
is not sufficient to prevent direct calls. Existing accounts are not repaired by
this constructor change; any such migration requires a separate design.

Before any separately authorized release, validate the target network's protocol
compatibility, factory RP ID, administration/governance permissions, artifact
hashes, API contract configuration, and creation/rotation flow on a test network.
Keep TESTNET and PUBLIC release records and configuration separate.

## Local validation results (2026-09-14)

- `make build`: passed; both optimized WASMs built with the pinned workspace.
- `make test`: passed, eight unit tests; WASM integration is intentionally ignored
  in this command and executed separately below.
- `make test-wasm`: passed, including factory EVM creation and authenticated
  passkey rotation using both release WASMs.
- `cargo fmt --all -- --check`: passed.
- `git diff --check`: passed.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: failed on
  existing `self_named_constructors` and `needless_borrow` warnings in
  `shared/src/upgrade_types.rs`. No warning suppression or unrelated contract
  refactoring was introduced to hide this failure.
- `cargo clippy --locked --workspace --all-targets`: completes with existing
  warnings across shared, upgrade, factory, and account code.

The restored build and focused regressions are verified locally. Strict lint is
not clean and a production deployment has not been approved or performed.

Two builds in independent output directories on the same host produced identical
SHA-256 hashes (cross-host reproduction has not been tested):

- Account: `98c4ee85e5bebc7d8af50c6354edf7a0dcb5510dd1c32f2d19a1a8ab205c22ba`
- Factory: `20dffdeac6e79f4e3df28b336322df673ba650a706e5371f12bca301b5c6f1ec`

The local `artifacts/rpid-initialization-2026-09-14/` directory contains both WASMs,
`SHA256SUMS`, `SOURCE_SHA256SUMS`, and `BUILD_PROVENANCE.json`. The provenance records
the base commit and explicitly identifies this as an uncommitted working-tree
build. This ignored directory is a local review bundle, not a published release.
