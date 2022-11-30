cd libwasmvm
cargo build -Z unstable-options --config net.git-fetch-with-cli=true --release --target aarch64-apple-darwin
lipo -output ../internal/api/libwasmvm.dylib -create target/aarch64-apple-darwin/release/deps/libwasmvm.dylib

cd ..
protoc --go_out=go_protobuf_gen --proto_path=libwasmvm/protobuf_contracts/ libwasmvm/protobuf_contracts/ffi.proto

go run ./cmd/demo/main.go
