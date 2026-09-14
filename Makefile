.PHONY: build test test-wasm fmt fmt-check lint clean

build:
	cargo build --locked --release --target wasm32v1-none -p socketfi-account -p socketfi-factory

test:
	cargo test --locked --workspace

test-wasm: build
	cargo test --locked -p socketfi-factory --test wasm_lifecycle -- --ignored

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

lint:
	cargo clippy --locked --workspace --all-targets -- -D warnings

clean:
	cargo clean
