package main

import (
	"errors"
	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	types "github.com/SigmaGmbH/librustgo/types"
	"google.golang.org/protobuf/proto"
	"github.com/holiman/uint256"
)

type MockedQueryHandler struct{}

var _ types.DataQuerier = MockedQueryHandler{}

func (MockedQueryHandler) Query(request []byte) ([]byte, error) {
	// Decode protobuf
	println("[Go:Query] Decoding protobuf")
	decodedRequest := &ffi.CosmosRequest{}
	if err := proto.Unmarshal(request, decodedRequest); err != nil {
		return nil, err
	}
	switch request := decodedRequest.Req.(type) {
	case *ffi.CosmosRequest_BlockHash:
		println("[Go:Query] Block hash")
		blockHash := uint256.NewInt(4).Bytes32()
		return proto.Marshal(&ffi.QueryBlockHashResponse{Hash: blockHash[:]})			
	// Handle request for account data such as balance and nonce
	case *ffi.CosmosRequest_GetAccount:
		println("[Go:Query] Requested data for address: ", request.GetAccount.Address)

		balance := uint256.NewInt(155).Bytes32()
		nonce := uint256.NewInt(133).Bytes32()

		return proto.Marshal(&ffi.QueryGetAccountResponse{
			Balance: balance[:],
			Nonce:   nonce[:],
		})
	// Handles request for updating account data
	case *ffi.CosmosRequest_InsertAccount:
		println("[Go:Query] Insert account")
		return proto.Marshal(&ffi.QueryInsertAccountResponse{})
	// Handles request if such account exists
	case *ffi.CosmosRequest_ContainsKey:
		println("[Go:Query] Contains key")
		return proto.Marshal(&ffi.QueryContainsKeyResponse{Contains: true})
	case *ffi.CosmosRequest_AccountCode:
		println("[Go:Query] Account code")
		return proto.Marshal(&ffi.QueryGetAccountCodeResponse{Code: make([]byte, 0)})
	case *ffi.CosmosRequest_StorageCell:
		println("[Go:Query] Get storage cell")
		return proto.Marshal(&ffi.QueryGetAccountStorageCellResponse{Value: make([]byte, 32)})
	case *ffi.CosmosRequest_InsertAccountCode:
		println("[Go:Query] Insert account code")
		return proto.Marshal(&ffi.QueryInsertAccountCodeResponse{})
	case *ffi.CosmosRequest_InsertStorageCell:
		println("[Go:Query] Insert storage cell")
		return proto.Marshal(&ffi.QueryInsertStorageCellResponse{})
	// Handles request for removing account from the storage
	case *ffi.CosmosRequest_Remove:
		println("[Go:Query] Remove account")
		return proto.Marshal(&ffi.QueryRemoveResponse{})
	case *ffi.CosmosRequest_RemoveStorageCell:
		println("[Go:Query] Remove storage cell")
		return proto.Marshal(&ffi.QueryRemoveStorageCellResponse{})
	}

	return nil, errors.New("wrong query")
}

// This is just a demo to ensure we can compile a static go binary
func main() {
	// TODO: Create new demo with usage of `call` and `create` methods
}
