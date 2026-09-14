.PHONY: build test fmt clean

build:
	cargo build --locked --release --target wasm32v1-none -p socketfi-access

test:
	cargo test --locked -p socketfi-access

fmt:
	cargo fmt -p socketfi-access

clean:
	cargo clean -p socketfi-access
