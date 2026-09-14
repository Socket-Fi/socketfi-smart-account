import json
from pathlib import Path
import tempfile
import unittest

import release


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.commit = "a" * 40

    def candidate(self, name, wasm=b"\0asm\x01\0\0\0fixture"):
        folder = self.root / name
        folder.mkdir()
        for name in release.WASMS:
            (folder / name).write_bytes(wasm)
        (folder / "source.tar").write_bytes(b"test source archive")
        for name in ("rustc-version.txt", "cargo-version.txt"):
            (folder / name).write_text("test version\n")
        manifest = {"schema": 1, "repository": release.REPOSITORY,
                    "commit": self.commit, "builder_image": release.IMAGE,
                    "platform": release.PLATFORM, "source_archive": "source.tar",
                    "source_sha256": release.digest(folder / "source.tar"),
                    "wasms": {n: release.digest(folder / n) for n in release.WASMS}}
        (folder / "build.json").write_text(json.dumps(manifest))
        return folder

    def test_identical_candidates_produce_checksums(self):
        one, two = self.candidate("one"), self.candidate("two")
        out = self.root / "verified"
        release.compare(one, two, out, self.commit)
        self.assertIn(release.digest(out / release.WASMS[0]), (out / "SHA256SUMS").read_text())

    def test_tampered_wasm_is_rejected(self):
        one = self.candidate("one")
        (one / release.WASMS[0]).write_bytes(b"\0asm\x01\0\0\0tampered")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            release.validate(one, self.commit)

    def test_tampered_source_is_rejected(self):
        one = self.candidate("one")
        (one / "source.tar").write_bytes(b"different source")
        with self.assertRaisesRegex(ValueError, "Source archive checksum"):
            release.validate(one, self.commit)

    def test_valid_but_different_builds_are_rejected(self):
        one = self.candidate("one")
        two = self.candidate("two", b"\0asm\x01\0\0\0different")
        with self.assertRaisesRegex(ValueError, "Independent builds differ"):
            release.compare(one, two, self.root / "verified", self.commit)
        self.assertFalse((self.root / "verified").exists())

    def test_wrong_commit_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unexpected commit"):
            release.validate(self.candidate("one"), "b" * 40)

    def test_wrong_repository_is_rejected(self):
        one = self.candidate("one")
        manifest = json.loads((one / "build.json").read_text())
        manifest["repository"] = "attacker/fork"
        (one / "build.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "Unexpected repository"):
            release.validate(one, self.commit)

    def test_existing_output_is_not_overwritten(self):
        one, two = self.candidate("one"), self.candidate("two")
        with self.assertRaisesRegex(ValueError, "Output must be empty"):
            release.compare(one, two, one, self.commit)


if __name__ == "__main__":
    unittest.main()
