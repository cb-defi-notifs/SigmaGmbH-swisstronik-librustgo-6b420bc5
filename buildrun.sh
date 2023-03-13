#!/usr/bin/env bash
export PATH=$PATH:$HOME/go/bin
set -e

cd sgx_evm || exit
cargo build --release --target aarch64-apple-darwin
cp ./target/aarch64-apple-darwin/release/libsgx_evm.dylib ../sgx_wrapper
cd ..

cd sgx_wrapper || exit

cargo build --release --target aarch64-apple-darwin
lipo -output ../internal/api/libsgx_wrapper.dylib -create target/aarch64-apple-darwin/release/deps/libsgx_wrapper.dylib

cd ..
protoc --go_out=go_protobuf_gen --proto_path=sgx_wrapper/protobuf_contracts/ sgx_wrapper/protobuf_contracts/ffi.proto

go run ./cmd/demo/main.go
