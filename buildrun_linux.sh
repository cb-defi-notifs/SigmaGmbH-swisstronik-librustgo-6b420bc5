#!/usr/bin/env bash
export PATH=$PATH:$HOME/go/bin
set -e

cd libwasmvm || exit

echo "Starting x86_64-unknown-linux-gnu build"
export CC=clang
export CXX=clang++
cargo build --release --target x86_64-unknown-linux-gnu
cp target/x86_64-unknown-linux-gnu/release/libwasmvm.so ../internal/api/libwasmvm.x86_64.so

cd ..
protoc --go_out=go_protobuf_gen --proto_path=libwasmvm/protobuf_contracts/ libwasmvm/protobuf_contracts/ffi.proto

go run ./cmd/demo/main.go
