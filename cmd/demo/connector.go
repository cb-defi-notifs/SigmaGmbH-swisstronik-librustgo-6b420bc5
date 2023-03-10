package main

import (
	"errors"
	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	"github.com/SigmaGmbH/librustgo/types"
	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/protobuf/proto"
)

type MockedConnector struct {
	db *MockedDB
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
		ethAddress := common.BytesToAddress(request.GetAccount.Address)
		println("[Go:Query] Requested data for address: ", ethAddress.String())
		acct, err := c.db.GetAccountOrEmpty(ethAddress)
		if err != nil {
			return nil, err
		}

		return proto.Marshal(&ffi.QueryGetAccountResponse{
			Balance: acct.Balance,
			Nonce:   acct.Nonce,
		})
	case *ffi.CosmosRequest_InsertAccount:
		data := request.InsertAccount
		ethAddress := common.BytesToAddress(request.InsertAccount.Address)
		println("[Go:Query] Insert/Update account: ", ethAddress.String())
		if err := c.db.InsertAccount(ethAddress, data.Balance, data.Nonce); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryInsertAccountResponse{})
	case *ffi.CosmosRequest_ContainsKey:
		println("[Go:Query] Contains key")
		ethAddress := common.BytesToAddress(request.ContainsKey.Key)
		contains, err := c.db.Contains(ethAddress)
		if err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryContainsKeyResponse{Contains: contains})
	case *ffi.CosmosRequest_AccountCode:
		println("[Go:Query] Account code")
		ethAddress := common.BytesToAddress(request.AccountCode.Address)
		acct, err := c.db.GetAccountOrEmpty(ethAddress)
		if err != nil {
			return nil, err
		}

		return proto.Marshal(&ffi.QueryGetAccountCodeResponse{Code: acct.Code})
	case *ffi.CosmosRequest_StorageCell:
		println("[Go:Query] Get storage cell")
		ethAddress := common.BytesToAddress(request.StorageCell.Address)
		value, err := c.db.GetStorageCell(ethAddress, request.StorageCell.Index)
		if err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryGetAccountStorageCellResponse{Value: value})
	case *ffi.CosmosRequest_InsertAccountCode:
		ethAddress := common.BytesToAddress(request.InsertAccountCode.Address)
		println("[Go:Query] Insert account code: ", ethAddress.String(), "len: ", len(request.InsertAccountCode.Code))
		if err := c.db.InsertContractCode(ethAddress, request.InsertAccountCode.Code); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryInsertAccountCodeResponse{})
	case *ffi.CosmosRequest_InsertStorageCell:
		println("[Go:Query] Insert storage cell")
		data := request.InsertStorageCell
		ethAddress := common.BytesToAddress(request.InsertStorageCell.Address)
		if err := c.db.InsertStorageCell(ethAddress, data.Index, data.Value); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryInsertStorageCellResponse{})
	case *ffi.CosmosRequest_Remove:
		println("[Go:Query] Remove account")
		ethAddress := common.BytesToAddress(request.Remove.Address)
		if err := c.db.Delete(ethAddress); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryRemoveResponse{})
	case *ffi.CosmosRequest_RemoveStorageCell:
		println("[Go:Query] Remove storage cell")
		ethAddress := common.BytesToAddress(request.RemoveStorageCell.Address)
		if err := c.db.InsertStorageCell(ethAddress, request.RemoveStorageCell.Index, make([]byte, 32)); err != nil {
			return nil, err
		}
		return proto.Marshal(&ffi.QueryRemoveStorageCellResponse{})
	}

	return nil, errors.New("wrong query")
}
