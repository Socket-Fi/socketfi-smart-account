#!/usr/bin/env python3
"""Build and compare release candidates; never sign transactions or deploy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

REPOSITORY = "Socket-Fi/socketfi-smart-account"
IMAGE = "docker.io/library/rust@sha256:307d198027388f780db83929487de35084a73ecbaa31319989438db38103439f"
PLATFORM = "linux/amd64"
WASMS = ("socketfi_account.wasm", "socketfi_factory.wasm")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def command(*args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def empty_output(path):
    path = Path(path).resolve()
    path.mkdir(parents=True, exist_ok=True)
    if any(path.iterdir()):
        raise ValueError(f"Output must be empty: {path}")
    return path


def build(output):
    root = Path(__file__).resolve().parents[1]
    if command("git", "status", "--porcelain", "--untracked-files=all", cwd=root):
        raise ValueError("Release builds require a clean committed checkout, including untracked files")
    commit = command("git", "rev-parse", "HEAD", cwd=root)
    if os.environ.get("GITHUB_SHA") and os.environ["GITHUB_SHA"] != commit:
        raise ValueError("Checkout does not match the GitHub workflow commit")
    out = empty_output(output)
    subprocess.run(["git", "archive", "--format=tar", "--prefix=socketfi-source/",
                    "--output", str(out / "source.tar"), commit], cwd=root, check=True)
    with tempfile.TemporaryDirectory(prefix="socketfi-build-input-") as temporary:
        inputs = Path(temporary)
        shutil.copyfile(out / "source.tar", inputs / "source.tar")
        # The executed build script comes from the same committed archive.
        script = subprocess.check_output(["git", "show", f"{commit}:scripts/build-contracts.sh"], cwd=root)
        (inputs / "build-contracts.sh").write_bytes(script)
        subprocess.run([
            "docker", "run", "--rm", "--platform", PLATFORM,
            "--mount", f"type=bind,source={inputs},target=/input,readonly",
            "--mount", f"type=bind,source={out},target=/output",
            IMAGE, "bash", "/input/build-contracts.sh",
        ], check=True)
    manifest = {
        "schema": 1, "repository": REPOSITORY, "commit": commit,
        "builder_image": IMAGE, "platform": PLATFORM,
        "source_archive": "source.tar", "source_sha256": digest(out / "source.tar"),
        "cargo_lock_sha256": digest(root / "Cargo.lock"),
        "build_script": "scripts/build-contracts.sh",
        "rustc": (out / "rustc-version.txt").read_text().strip(),
        "cargo": (out / "cargo-version.txt").read_text().strip(),
        "wasms": {name: digest(out / name) for name in WASMS},
        "external_optimizer": None,
        "checks": ["format", "strict-clippy", "workspace-unit-tests", "release-wasm-lifecycle"],
    }
    (out / "build.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"Built commit {commit} into {out}")


def validate(directory, commit):
    directory = Path(directory)
    data = json.loads((directory / "build.json").read_text())
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Expected a full 40-character commit SHA")
    for key, expected in {"schema": 1, "repository": REPOSITORY, "commit": commit,
                          "builder_image": IMAGE, "platform": PLATFORM,
                          "source_archive": "source.tar"}.items():
        if data.get(key) != expected:
            raise ValueError(f"Unexpected {key} in {directory}")
    if data.get("source_sha256") != digest(directory / "source.tar"):
        raise ValueError("Source archive checksum mismatch")
    if set(data.get("wasms", {})) != set(WASMS):
        raise ValueError("Expected exactly the account and factory artifacts")
    for name in WASMS:
        artifact = directory / name
        if artifact.read_bytes()[:8] != b"\0asm\x01\0\0\0":
            raise ValueError(f"Invalid WASM header: {name}")
        if data["wasms"][name] != digest(artifact):
            raise ValueError(f"WASM checksum mismatch: {name}")
    return data


def compare(first, second, output, commit):
    left, right = validate(first, commit), validate(second, commit)
    if left != right:
        raise ValueError("Independent builds differ; refusing to prepare attestations")
    out = empty_output(output)
    for name in (*WASMS, "source.tar", "build.json", "rustc-version.txt", "cargo-version.txt"):
        shutil.copyfile(Path(first) / name, out / name)
    names = (*WASMS, "source.tar", "build.json", "rustc-version.txt", "cargo-version.txt")
    (out / "SHA256SUMS").write_text("".join(f"{digest(out / name)}  {name}\n" for name in names))
    print(f"Both isolated builds match for {commit}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    build_parser = sub.add_parser("build")
    build_parser.add_argument("--output", required=True)
    compare_parser = sub.add_parser("compare")
    for name in ("first", "second", "output", "commit"):
        compare_parser.add_argument(f"--{name}", required=True)
    args = vars(parser.parse_args())
    action = args.pop("action")
    try:
        (build if action == "build" else compare)(**args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Release verification failed: {error}\n")


if __name__ == "__main__":
    main()
