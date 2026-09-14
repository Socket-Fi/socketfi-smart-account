#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 4 ]]; then
  echo 'Usage: bash scripts/verify-deployment.sh testnet|mainnet FULL_COMMIT_SHA FACTORY_ID ACCOUNT_ID' >&2
  exit 2
fi
network=$1
commit=$2
factory=$3
account=$4
case "$network" in testnet|mainnet) ;; *) echo 'Unknown network' >&2; exit 2 ;; esac
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || { echo 'A full commit SHA is required' >&2; exit 2; }
[[ "$factory" =~ ^C[A-Z2-7]{55}$ && "$account" =~ ^C[A-Z2-7]{55}$ ]] || {
  echo 'Factory and account must be Stellar contract addresses' >&2; exit 2;
}
output=$(mktemp -d "${TMPDIR:-/tmp}/socketfi-deployment-verification.XXXXXX")
for kind in factory account; do
  if [[ "$kind" == factory ]]; then address=$factory; else address=$account; fi
  stellar contract fetch --network "$network" --id "$address" --out-file "$output/$kind.wasm"
  gh attestation verify "$output/$kind.wasm" \
    --repo Socket-Fi/socketfi-smart-account \
    --signer-workflow Socket-Fi/socketfi-smart-account/.github/workflows/verified-release.yml \
    --source-digest "$commit" \
    --deny-self-hosted-runners --format json > "$output/$kind-attestation.json"
  python3 - "$output/$kind.wasm" "$output/$kind-attestation.json" "socketfi_$kind.wasm" <<'PYVERIFY'
import hashlib, json, sys
from pathlib import Path
wasm, evidence, expected_name = sys.argv[1:]
digest = hashlib.sha256(Path(wasm).read_bytes()).hexdigest()
results = json.loads(Path(evidence).read_text())
subjects = [subject for result in results
            for subject in result["verificationResult"]["statement"]["subject"]]
if not any(s["name"] == expected_name and s["digest"].get("sha256") == digest for s in subjects):
    raise SystemExit("Attested bytes do not match the expected account/factory artifact role")
PYVERIFY
done
printf 'Verified code provenance for both contracts on %s at commit %s.\nEvidence: %s\n' "$network" "$commit" "$output"
echo 'This verifies current code, not account registration, RP configuration, ownership, or future upgrades.'
