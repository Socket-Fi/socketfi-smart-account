.PHONY: build test fmt clean

build:
	cargo build --locked --release --target wasm32v1-none -p socketfi-shared

test:
	cargo test --locked -p socketfi-shared

fmt:
	cargo fmt -p socketfi-shared

clean:
	cargo clean -p socketfi-shared
