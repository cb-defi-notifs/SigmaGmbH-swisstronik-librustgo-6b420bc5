package main

import (
	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	"github.com/SigmaGmbH/librustgo/internal/api"
	"github.com/ethereum/go-ethereum/common"
)

// This is just a demo to ensure we can compile a static go binary
func main() {
	db := CreateMockedDatabase()
	connector := MockedConnector{db}

	from := common.HexToAddress("0x690b9a9e9aa1c9db991c7721a92d351db4fac990")
	value := common.Hex2Bytes("0x00")
	data := common.Hex2Bytes("0x00") // TODO: Replace with data for deployment of `Counter` contract
	gasLimit := uint64(2000000)
	txContext := getDefaultTxContext()

	_, err := api.Create(
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

	// TODO: Call `add` method
	// TODO: Make a query to contract to obtain current `count` value
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
