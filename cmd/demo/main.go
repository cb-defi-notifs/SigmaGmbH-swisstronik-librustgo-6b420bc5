package main

import (
	"encoding/hex"
	"errors"
	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	"github.com/SigmaGmbH/librustgo/internal/api"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"google.golang.org/protobuf/proto"
)

// This is just a demo to ensure we can compile a static go binary
func main() {
	db := CreateMockedDatabase()
	from := common.HexToAddress("0x690b9a9e9aa1c9db991c7721a92d351db4fac990")

	contractAddress, err := DeployCounterContract(from, &db)
	if err != nil {
		panic(err)
	}

	err = CallAddMethod(from, contractAddress, &db)
	if err != nil {
		panic(err)
	}

	err = QueryCounterValue(from, contractAddress, &db)
	if err != nil {
		panic(err)
	}
}

func DeployCounterContract(from common.Address, db *MockedDB) (common.Address, error) {
	println("\nDeployCounterContract\n")
	connector := MockedConnector{db}
	value := common.Hex2Bytes("00")
	data := common.Hex2Bytes("60806040526000805534801561001457600080fd5b50610394806100246000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c80634f2be91f1461004657806361bc221a146100505780636deebae31461006e575b600080fd5b61004e610078565b005b610058610103565b60405161006591906101f1565b60405180910390f35b610076610109565b005b60008081548092919061008a9061023b565b91905055507f64a55044d1f2eddebe1b90e8e2853e8e96931cefadbfa0b2ceb34bee360619416000546040516100c091906101f1565b60405180910390a17f938d2ee5be9cfb0f7270ee2eff90507e94b37625d9d2b3a61c97d30a4560b8296000546040516100f991906101f1565b60405180910390a1565b60005481565b60008054116040518060400160405280600f81526020017f434f554e5445525f544f4f5f4c4f57000000000000000000000000000000000081525090610185576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161017c9190610313565b60405180910390fd5b5060008081548092919061019890610335565b91905055507f938d2ee5be9cfb0f7270ee2eff90507e94b37625d9d2b3a61c97d30a4560b8296000546040516101ce91906101f1565b60405180910390a1565b6000819050919050565b6101eb816101d8565b82525050565b600060208201905061020660008301846101e2565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000610246826101d8565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036102785761027761020c565b5b600182019050919050565b600081519050919050565b600082825260208201905092915050565b60005b838110156102bd5780820151818401526020810190506102a2565b60008484015250505050565b6000601f19601f8301169050919050565b60006102e582610283565b6102ef818561028e565b93506102ff81856020860161029f565b610308816102c9565b840191505092915050565b6000602082019050818103600083015261032d81846102da565b905092915050565b6000610340826101d8565b9150600082036103535761035261020c565b5b60018203905091905056fea264697066735822122009b7dbde115b8323afdd451cd1b9c02d5e332011af0eb72b9ef71469fe56ab3564736f6c63430008120033")
	gasLimit := uint64(2000000)
	txContext := getDefaultTxContext()

	// Calculate contract address
	fromAcct, err := db.GetAccountOrEmpty(from)
	if err != nil {
		return common.Address{}, err
	}
	contractAddress := crypto.CreateAddress(from, fromAcct.Nonce)

	// Deploy contract
	_, err = api.Create(
		connector,
		from.Bytes(),
		data,
		value,
		nil,
		gasLimit,
		txContext,
		true,
	)
	if err != nil {
		panic(err)
	}

	// Check if contract was deployed correctly
	acct, _ := db.GetAccountOrEmpty(contractAddress)
	if len(acct.Code) == 0 {
		return common.Address{}, errors.New("contract was not deployed")
	}

	return contractAddress, nil
}

func CallAddMethod(from common.Address, contractAddress common.Address, db *MockedDB) error {
	println("\nCallAddMethod\n")
	connector := MockedConnector{db}
	value := common.Hex2Bytes("00")
	data := common.Hex2Bytes("4f2be91f")
	gasLimit := uint64(2000000)
	txContext := getDefaultTxContext()

	res, err := api.Call(
		connector,
		from.Bytes(),
		contractAddress.Bytes(),
		data,
		value,
		nil,
		gasLimit,
		txContext,
		true,
	)
	if err != nil {
		return err
	}

	// Check if transaction was executed correctly
	if res.GasUsed <= 21000 {
		return errors.New("incorrect gas calculation")
	}
	if res.VmError != "" {
		return errors.New("got non-empty VM error")
	}
	if len(res.Logs) != 2 {
		return errors.New("incorrect logs")
	}

	return nil
}

func QueryCounterValue(from common.Address, contractAddress common.Address, db *MockedDB) error {
	println("\nQueryCounterValue\n")
	connector := MockedConnector{db}
	data := common.Hex2Bytes("61bc221a")
	value := common.Hex2Bytes("00")
	gasLimit := uint64(2000000)
	txContext := getDefaultTxContext()
	res, err := api.Call(
		connector,
		from.Bytes(),
		contractAddress.Bytes(),
		data,
		value,
		nil,
		gasLimit,
		txContext,
		false, // commit = false, because we're doing a query to contract
	)
	if err != nil {
		return err
	}
	println("Request result: ", hex.EncodeToString(res.Ret))
	return nil
}

func getDefaultTxContext() *ffi.TransactionContext {
	return &ffi.TransactionContext{
		BlockCoinbase:      common.Address{}.Bytes(),
		BlockNumber:        0,
		BlockBaseFeePerGas: make([]byte, 32),
		Timestamp:          0,
		BlockGasLimit:      100000000000,
		ChainId:            1,
		GasPrice:           make([]byte, 32),
	}
}

// Additional function to debug connector.
// TODO: Should be removed when demo command will be finished
func debugConnector() {
	db := CreateMockedDatabase()
	connector := MockedConnector{&db}

	// Set account
	request := &ffi.CosmosRequest{Req: &ffi.CosmosRequest_InsertAccount{InsertAccount: &ffi.QueryInsertAccount{
		Address: common.Address{}.Bytes(),
		Balance: make([]byte, 32),
		Nonce:   10,
	}}}
	byteRequest, err := proto.Marshal(request)
	if err != nil {
		panic(err)
	}
	_, err = connector.Query(byteRequest)
	if err != nil {
		panic(err)
	}

	// Check if account was added correctly
	acct, err := db.GetAccountOrEmpty(common.Address{})
	if err != nil {
		panic(err)
	}
	if acct.Nonce != 10 {
		panic("Account was not added")
	}

	// Set contract code
	request = &ffi.CosmosRequest{Req: &ffi.CosmosRequest_InsertAccountCode{InsertAccountCode: &ffi.QueryInsertAccountCode{
		Address: common.Address{}.Bytes(),
		Code:    make([]byte, 100),
	}}}
	byteRequest, err = proto.Marshal(request)
	if err != nil {
		panic(err)
	}
	_, err = connector.Query(byteRequest)
	if err != nil {
		panic(err)
	}

	// Check if contract code was set correctly
	acct, err = db.GetAccountOrEmpty(common.Address{})
	if len(acct.Code) != 100 {
		panic("Contract was not deployed")
	}

	// Check request for empty account. Should not fail
	debugAddress := common.HexToAddress("0x690b9a9e9aa1c9db991c7721a92d351db4fac990")
	request = &ffi.CosmosRequest{Req: &ffi.CosmosRequest_GetAccount{GetAccount: &ffi.QueryGetAccount{Address: debugAddress.Bytes()}}}
	byteRequest, err = proto.Marshal(request)
	if err != nil {
		panic(err)
	}
	result, err := connector.Query(byteRequest)
	if err != nil {
		panic(err)
	}

	accountRequestResult := &ffi.QueryGetAccountResponse{}
	_ = proto.Unmarshal(result, accountRequestResult)
	if accountRequestResult.Nonce != 0 {
		panic("Invalid nonce for non-existing account")
	}

	// Insert storage cell
	addressToInsert := common.Address{}
	index := common.HexToHash("0xd09ed9e011d94ef50c41905a4cefd67f1d35ddd6f077803a25115eea8d194d35")
	value := common.HexToHash("0x6cb73911b6666201be60d0db3936aef746074d13fd1fdca845f680e9c76563dd")
	request = &ffi.CosmosRequest{Req: &ffi.CosmosRequest_InsertStorageCell{InsertStorageCell: &ffi.QueryInsertStorageCell{
		Address: addressToInsert.Bytes(),
		Index:   index.Bytes(),
		Value:   value.Bytes(),
	}}}
	byteRequest, _ = proto.Marshal(request)
	_, err = connector.Query(byteRequest)
	if err != nil {
		panic(err)
	}

	// Check if storage cell was set
	getStorageCellRes, err := connector.db.GetStorageCell(addressToInsert, index.Bytes())
	println("Cell value", common.BytesToHash(getStorageCellRes).String())
}
