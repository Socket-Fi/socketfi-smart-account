.PHONY: build test fmt clean

build:
	cargo build --locked --release --target wasm32v1-none -p socketfi-account

test:
	cargo test --locked -p socketfi-account

fmt:
	cargo fmt -p socketfi-account

clean:
	cargo clean -p socketfi-account
