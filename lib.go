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

// Export protobuf messages for FFI
type QueryGetAccount = ffi.QueryGetAccount
type QueryGetAccountResponse = ffi.QueryGetAccountResponse
type CosmosRequest = ffi.CosmosRequest
type QueryInsertAccount = ffi.QueryInsertAccount
type QueryInsertAccountResponse = ffi.QueryInsertAccountResponse
type QueryContainsKey = ffi.QueryContainsKey
type QueryContainsKeyResponse = ffi.QueryContainsKeyResponse
type QueryGetAccountStorageCell = ffi.QueryGetAccountStorageCell
type QueryGetAccountStorageCellResponse = ffi.QueryGetAccountStorageCellResponse
type QueryGetAccountCode = ffi.QueryGetAccountCode
type QueryGetAccountCodeResponse = ffi.QueryGetAccountCodeResponse
type QueryInsertAccountCode = ffi.QueryInsertAccountCode
type QueryInsertAccountCodeResponse = ffi.QueryInsertAccountCodeResponse
type QueryInsertStorageCell = ffi.QueryInsertStorageCell
type QueryInsertStorageCellResponse = ffi.QueryInsertStorageCellResponse
type QueryRemove = ffi.QueryRemove
type QueryRemoveResponse = ffi.QueryRemoveResponse
type QueryRemoveStorageCell = ffi.QueryRemoveStorageCell
type QueryRemoveStorageCellResponse = ffi.QueryRemoveStorageCellResponse
type QueryBlockHash = ffi.QueryBlockHash
type QueryBlockHashResponse = ffi.QueryBlockHashResponse
type QueryBlockTimestamp = ffi.QueryBlockTimestamp
type QueryBlockTimestampResponse = ffi.QueryBlockTimestampResponse
type QueryBlockNumber = ffi.QueryBlockNumber
type QueryBlockNumberResponse = ffi.QueryBlockNumberResponse
type QueryChainId = ffi.QueryChainId
type QueryChainIdResponse = ffi.QueryChainIdResponse

// Storage requests
type CosmosRequest_GetAccount = ffi.CosmosRequest_GetAccount
type CosmosRequest_InsertAccount = ffi.CosmosRequest_InsertAccount
type CosmosRequest_ContainsKey = ffi.CosmosRequest_ContainsKey
type CosmosRequest_AccountCode = ffi.CosmosRequest_AccountCode
type CosmosRequest_StorageCell = ffi.CosmosRequest_StorageCell
type CosmosRequest_InsertAccountCode = ffi.CosmosRequest_InsertAccountCode
type CosmosRequest_InsertStorageCell = ffi.CosmosRequest_InsertStorageCell
type CosmosRequest_Remove = ffi.CosmosRequest_Remove
type CosmosRequest_RemoveStorageCell = ffi.CosmosRequest_RemoveStorageCell
// Backend requests
type CosmosRequest_BlockNumber = ffi.CosmosRequest_BlockNumber
type CosmosRequest_BlockHash = ffi.CosmosRequest_BlockHash
type CosmosRequest_BlockTimestamp = ffi.CosmosRequest_BlockTimestamp
type CosmosRequest_ChainId = ffi.CosmosRequest_ChainId

func HandleTx(querier types.DataQuerier, from, to, data, value []byte, gasLimit uint64) (*ffi.HandleTransactionResponse, error) {
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
