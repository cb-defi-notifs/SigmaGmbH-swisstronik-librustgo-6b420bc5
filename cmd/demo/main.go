package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	wasmvm "github.com/SigmaGmbH/librustgo"
	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	types "github.com/SigmaGmbH/librustgo/types"
	"github.com/holiman/uint256"
	"google.golang.org/protobuf/proto"
)

//const (
//	SUPPORTED_FEATURES = "staking"
//	PRINT_DEBUG        = true
//	MEMORY_LIMIT       = 32  // MiB
//	CACHE_SIZE         = 100 // MiB
//)

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
	// Create sample execution data
	from, decodingErr := hex.DecodeString("91e1f4Bb1C1895F6c65cD8379DE1323A8bF3Cf7c")
	if decodingErr != nil {
		panic(decodingErr)
	}
	to, decodingErr := hex.DecodeString("91b126ff9AF242408090A223829Eb88A61724AA5")
	if decodingErr != nil {
		panic(decodingErr)
	}

	value := make([]byte, 8)
	binary.BigEndian.PutUint64(value, uint64(1)) // sends 1 wei
	gasLimit := uint64(10000000)
	data := make([]byte, 0)
	querier := &MockedQueryHandler{}

	result, err := wasmvm.HandleTx(querier, from, to, data, value, gasLimit)
	//err := wasmvm.HelloWorld("Admin")
	//file := os.Args[1]
	//fmt.Printf("Running %s...\n", file)
	//bz, err := ioutil.ReadFile(file)
	if err != nil {
		panic(err)
	}
	fmt.Println("GO: execution result: ", result)
	//fmt.Println("Loaded!")
	//
	//os.MkdirAll("tmp", 0o755)
	//
	//vm, err := wasmvm.NewVM("tmp", SUPPORTED_FEATURES, MEMORY_LIMIT, PRINT_DEBUG, CACHE_SIZE)
	//if err != nil {
	//	panic(err)
	//}
	//
	//checksum, err := vm.Create(bz)
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Printf("Stored code with checksum: %X\n", checksum)
	//
	//vm.Cleanup()
	//fmt.Println("finished")
}
