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
	case *ffi.CosmosRequest_InsertAccount:
		println("[Go:Query] Insert account")
		data := request.InsertAccount
		if err := c.db.InsertAccount(data.Address, data.Balance, data.Nonce); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryInsertAccountResponse{})
	case *ffi.CosmosRequest_ContainsKey:
		println("[Go:Query] Contains key")
		contains, err := c.db.Contains(request.ContainsKey.Key)
		if err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryContainsKeyResponse{Contains: contains})
	case *ffi.CosmosRequest_AccountCode:
		println("[Go:Query] Account code")
		acct, err := c.db.GetAccountOrEmpty(request.AccountCode.Address)
		if err != nil {
			return nil, err
		}

		return proto.Marshal(&ffi.QueryGetAccountCodeResponse{Code: acct.Code})
	case *ffi.CosmosRequest_StorageCell:
		println("[Go:Query] Get storage cell")
		value, err := c.db.GetStorageCell(request.StorageCell.Address, request.StorageCell.Index)
		if err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryGetAccountStorageCellResponse{Value: value})
	case *ffi.CosmosRequest_InsertAccountCode:
		println("[Go:Query] Insert account code")
		if err := c.db.InsertContractCode(request.InsertAccountCode.Address, request.InsertAccountCode.Code); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryInsertAccountCodeResponse{})
	case *ffi.CosmosRequest_InsertStorageCell:
		println("[Go:Query] Insert storage cell")
		data := request.InsertStorageCell
		if err := c.db.InsertStorageCell(data.Address, data.Index, data.Value); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryInsertStorageCellResponse{})
	case *ffi.CosmosRequest_Remove:
		println("[Go:Query] Remove account")
		if err := c.db.Delete(request.Remove.Address); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryRemoveResponse{})
	case *ffi.CosmosRequest_RemoveStorageCell:
		println("[Go:Query] Remove storage cell")
		if err := c.db.InsertStorageCell(request.RemoveStorageCell.Address, request.RemoveStorageCell.Index, make([]byte, 32)); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryRemoveStorageCellResponse{})
	}

	return nil, errors.New("wrong query")
}
