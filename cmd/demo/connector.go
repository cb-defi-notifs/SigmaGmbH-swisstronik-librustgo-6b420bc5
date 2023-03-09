package main

import (
	"errors"
	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	"github.com/SigmaGmbH/librustgo/types"
	"google.golang.org/protobuf/proto"
)

type MockedConnector struct {
	db MockedDB
}

var _ types.Connector = MockedConnector{}

func (c MockedConnector) Query(request []byte) ([]byte, error) {
	// Decode protobuf
	println("[Go:Query] Decoding protobuf")
	decodedRequest := &ffi.CosmosRequest{}
	if err := proto.Unmarshal(request, decodedRequest); err != nil {
		return nil, err
	}
	switch request := decodedRequest.Req.(type) {
	case *ffi.CosmosRequest_BlockHash:
		println("[Go:Query] Block hash")
		blockHash := make([]byte, 32)
		return proto.Marshal(&ffi.QueryBlockHashResponse{Hash: blockHash})
	case *ffi.CosmosRequest_GetAccount:
		println("[Go:Query] Requested data for address: ", request.GetAccount.Address)
		acct, err := c.db.GetAccountOrEmpty(request.GetAccount.Address)
		if err != nil {
			return nil, err
		}

		return proto.Marshal(&ffi.QueryGetAccountResponse{
			Balance: acct.Balance,
			Nonce:   acct.Nonce,
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
