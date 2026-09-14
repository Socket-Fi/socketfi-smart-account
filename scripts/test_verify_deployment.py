"""Exercise the read-only verifier's failure boundaries without RPC or credentials."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class DeploymentVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.script = Path(__file__).with_name("verify-deployment.sh")
        self.environment = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                                TMPDIR=str(self.root))
        self.tool("stellar", '''
from pathlib import Path
import sys
assert sys.argv[1:3] == ["contract", "fetch"]
Path(sys.argv[sys.argv.index("--out-file") + 1]).write_bytes(b"\\0asm\\x01\\0\\0\\0fixture")
''')
        self.tool("gh", '''
import hashlib, json, os, sys
from pathlib import Path
assert sys.argv[1:3] == ["attestation", "verify"]
for flag in ("--repo", "--signer-workflow", "--source-digest", "--deny-self-hosted-runners"):
    assert flag in sys.argv
if os.environ.get("FAIL_ATTESTATION"):
    sys.exit(1)
artifact = Path(sys.argv[3])
name = "socketfi_" + artifact.name
if os.environ.get("WRONG_ROLE"):
    name = "socketfi_other.wasm"
print(json.dumps([{"verificationResult": {"statement": {"subject": [{
    "name": name, "digest": {"sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}
}]}}}]))
''')

    def tool(self, name, content):
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n" + content)
        path.chmod(0o755)

    def run_verifier(self, network="testnet", **environment):
        return subprocess.run(["bash", str(self.script), network, "a" * 40,
                               "C" + "A" * 55, "C" + "B" * 55],
                              env=dict(self.environment, **environment), capture_output=True, text=True)

    def test_both_verified_roles_succeed(self):
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Verified code provenance", result.stdout)

    def test_unknown_network_is_rejected(self):
        result = self.run_verifier("public-typo")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Unknown network", result.stderr)

    def test_failed_attestation_cannot_report_success(self):
        result = self.run_verifier(FAIL_ATTESTATION="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("Verified code provenance", result.stdout)

    def test_attested_wrong_artifact_role_is_rejected(self):
        result = self.run_verifier(WRONG_ROLE="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("expected account/factory artifact role", result.stderr)


if __name__ == "__main__":
    unittest.main()
