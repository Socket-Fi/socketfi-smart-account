#!/usr/bin/env bash
set -euo pipefail
# Run only inside the pinned builder. No host credentials or Docker socket mounted.
mkdir -p /build
tar -xf /input/source.tar -C /build
cd /build/socketfi-source
rustup target add wasm32v1-none --toolchain 1.91.0
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --release --target wasm32v1-none -p socketfi-account -p socketfi-factory
cargo test --locked -p socketfi-factory --test wasm_lifecycle -- --ignored
cp target/wasm32v1-none/release/socketfi_account.wasm /output/
cp target/wasm32v1-none/release/socketfi_factory.wasm /output/
rustc --version > /output/rustc-version.txt
cargo --version > /output/cargo-version.txt
