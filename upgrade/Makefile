.PHONY: build test fmt clean

build:
	cargo build --locked --release --target wasm32v1-none -p upgrade

test:
	cargo test --locked -p upgrade

fmt:
	cargo fmt -p upgrade

clean:
	cargo clean -p upgrade
