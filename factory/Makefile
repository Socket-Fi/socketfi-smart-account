.PHONY: build test fmt clean

build:
	cargo build --locked --release --target wasm32v1-none -p socketfi-factory

test:
	cargo test --locked -p socketfi-factory

fmt:
	cargo fmt -p socketfi-factory

clean:
	cargo clean -p socketfi-factory
