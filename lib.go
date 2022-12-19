package librustgo

import (
	"github.com/SigmaGmbH/librustgo/internal/api"
	"github.com/SigmaGmbH/librustgo/types"

	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
)

// Checksum represents a hash of the Wasm bytecode that serves as an ID. Must be generated from this library.
type Checksum []byte

// WasmCode is an alias for raw bytes of the wasm compiled code
type WasmCode []byte

// KVStore is a reference to some sub-kvstore that is valid for one instance of a code
type KVStore = api.KVStore

// GoAPI is a reference to some "precompiles", go callbacks
type GoAPI = api.GoAPI

// Querier lets us make read-only queries on other modules
type Querier = types.Querier

// GasMeter is a read-only version of the sdk gas meter
type GasMeter = api.GasMeter

func HandleTx(querier *types.DataQuerier, from, to, data, value []byte, gasLimit uint64) (*ffi.HandleTransactionResponse, error) {
	executionResult, err := api.HandleTx(querier, from, to, data, value, gasLimit)
	if err != nil {
		return &ffi.HandleTransactionResponse{}, err
	}

	return executionResult, nil
}

// LibwasmvmVersion returns the version of the loaded library
// at runtime. This can be used for debugging to verify the loaded version
// matches the expected version.
func LibwasmvmVersion() (string, error) {
	return api.LibwasmvmVersion()
}
