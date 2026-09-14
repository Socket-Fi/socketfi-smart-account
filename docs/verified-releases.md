# Verified contract releases

The release workflow builds both contracts twice in isolated GitHub-hosted jobs,
compares the exact bytes and source manifests, then creates GitHub/Sigstore build
attestations. It does not deploy, create Stellar keys, or receive deployment secrets.

## Maintainer setup

Before treating a release as canonical:

1. Protect `main`, `.github/workflows/`, the release scripts, and `contracts-v*`
   tags with repository rules requiring trusted review. Restrict release-tag
   creation and workflow changes to release maintainers. These GitHub settings
   are not configured by adding this workflow file.
2. Confirm GitHub Actions and artifact attestations are available for this repo.
   Public repositories support attestations on current GitHub plans; private
   repositories require an eligible plan.
3. Review and merge the workflow, metadata, and build changes. The exact release
   commit must contain them. Do not attest an old artifact under a newer commit.
4. Run **Verified contract release** from `main`, or push a reviewed
   `contracts-v*` release tag. Both builds and the attestation job must succeed.

Actions are pinned to immutable commits. The Rust 1.91.0 Bookworm Linux/amd64
builder is pinned to its single-platform image digest in `scripts/release.py`.
Rustup installs the pinned toolchain's WASM target; Cargo uses the committed lock.
No build cache, host Cargo directory, host credentials, or Docker socket is
mounted inside the builder. Dependency downloads require network access.

The workflow requires formatting, strict Clippy (`-D warnings`), workspace unit
tests, and the real-signature WASM lifecycle test. Mechanical Clippy warnings are
fixed. Documented exceptions preserve public helper names, the serialized `RPID`
storage name, and existing ABI argument lists. The argument-count exception is
scoped to contract entrypoint modules because Soroban generates wrappers outside
the annotated impl; unrelated lint categories remain enforced. Provenance and
passing focused tests do not constitute a security audit.

## Release output

Download `socketfi-verified-<full-commit>` from the successful run. It contains:

- `socketfi_account.wasm` and `socketfi_factory.wasm`;
- `source.tar`, a `git archive` of that exact commit;
- `build.json`, including commit, source digest, builder digest, tool versions,
  lockfile checksum, and both artifact hashes;
- toolchain version files, `SHA256SUMS`, and `attestation.json`.

The workflow attests all checksum subjects. The checksum file is a convenience;
it is not itself a signature. Verify the attestation of the WASMs, source archive,
and build manifest before trusting their contents. Publish the complete bundle as
assets of the reviewed GitHub Release: workflow artifacts expire after 90 days.
Release creation/publication is deliberately a separate maintainer action.

Both WASMs contain `source_repo=github:Socket-Fi/socketfi-smart-account`, using
SEP-0055 discovery metadata. The signed attestation identifies the exact commit.
Metadata is included before tests, checksum comparison, and attestation. It
changes the previous RP-ID release hashes; those earlier hashes are not the
hashes of these new release artifacts. Metadata alone is not proof.

## Independent reproduction

On a clean checkout of the full release commit with Docker and Python 3:

```bash
python3 -B scripts/release.py build --output artifacts/reproduction
```

Compare both WASM hashes and `source.tar` with the verified release. Native macOS
outputs were observed to differ from the Linux container outputs; use this pinned
container recipe for canonical release reproduction, rather than a native build. The build
rejects modified or untracked source and a nonempty output directory. The build
script is executed from the exact committed source archive in the pinned image.
Two GitHub builds test reproducibility but share GitHub and the same builder trust
base. A third-party rebuild provides additional independent evidence.

This implements SEP-0055 attestation discovery and a documented reproducible
recipe; it does not claim SEP-0058 container/metadata conformance.

## Verify before deployment

Set `RELEASE_COMMIT` to the independently selected full release commit:

```bash
gh attestation verify socketfi_account.wasm \
  --repo Socket-Fi/socketfi-smart-account \
  --signer-workflow Socket-Fi/socketfi-smart-account/.github/workflows/verified-release.yml \
  --source-digest "$RELEASE_COMMIT" --deny-self-hosted-runners
```

Repeat for `socketfi_factory.wasm`, `source.tar`, and `build.json`. The workflow
and expected commit constraints matter: accepting any attestation from the repo
is weaker than accepting the reviewed release. Retain the Sigstore JSON bundle for
offline verification with GitHub CLI's `--bundle` option and trusted Sigstore
roots. A verifier must still trust the repository/workflow and GitHub's identity
issuer; the independent rebuild complements that trust.

Only deploy those final WASMs. Disable any additional CLI optimization using
`--optimize=false`; do not rebuild or append metadata after attestation. Deployment
keys belong in a separate local secure store or a separately approved deployment
process, never this build workflow. No deployment key is needed to attest builds.

## Verify after deployment

```bash
bash scripts/verify-deployment.sh testnet "$RELEASE_COMMIT" "$FACTORY_ID" "$ACCOUNT_ID"
```

This read-only helper fetches the currently installed WASM for both addresses and
requires the expected repository, workflow, and source commit in their attestations.
Unknown networks, malformed IDs, failed fetches, or failed attestations stop it.
Save the resulting verification evidence with a release deployment record containing
the network passphrase, contract addresses, transaction hashes, RP ID, admin and
approved-account WASM hash. Check `get_latest_account_wasm` separately against the
released account hash: factory code provenance does not prove its mutable settings.

An account with matching code is not automatically registered by the canonical
SocketFi factory. Check the factory registry and account's factory association
separately. A signer can authorize later account upgrades; verify again after
upgrades and retain the network/ledger context of each verification.

References: [SEP-0055](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0055.md),
[GitHub attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).

## Local validation of this implementation

- `python3 -B -m unittest discover -s scripts -p 'test_*.py'`: 11 passed,
  including artifact/source tampering, wrong commit/repository, differing builds,
  failed attestations, unknown networks, and wrong account/factory artifact roles.
- `bash -n scripts/build-contracts.sh scripts/verify-deployment.sh`: passed.
- `actionlint .github/workflows/verified-release.yml` (1.7.12): passed.
- `cargo fmt --all -- --check`: passed.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: passed after
  mechanical fixes and compatibility exceptions; required by release builds.
- `make test`: eight unit tests passed.
- `make test-wasm`: both metadata-bearing release WASMs built and the real-signature
  EVM-to-passkey lifecycle test passed.
- `stellar contract info meta --wasm <artifact>`: confirmed the correct
  `source_repo` metadata in both native artifacts.
- `python3 -B scripts/release.py build --output <candidate>`: executed twice from
  the same clean temporary source snapshot in separate pinned Docker containers.
  Both runs passed formatting, strict Clippy, all eight unit tests, and the WASM lifecycle test.
- `python3 -B scripts/release.py compare --first <first> --second <second>
  --output <verified> --commit <snapshot-commit>`: passed; source archives,
  manifests, and both WASMs matched exactly.
- Dirty-checkout release build rejection and `git diff --check`: passed.
- Account and factory contract interface JSON compared before/after the lint
  cleanup: identical when documentation fields are excluded. No ABI or serialized
  storage names were changed.

The temporary snapshot used for local container validation is not an official
release commit. No GitHub attestation has been issued by these local tests.
The GitHub-hosted signing step and live deployed-code verification must be checked
once the workflow is pushed and run. No contract was deployed or upgraded.
