package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	wasmvm "github.com/SigmaGmbH/librustgo"
	types "github.com/SigmaGmbH/librustgo/types"
	"github.com/holiman/uint256"
	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	"github.com/golang/protobuf/proto"
)

const (
	SUPPORTED_FEATURES = "staking"
	PRINT_DEBUG        = true
	MEMORY_LIMIT       = 32  // MiB
	CACHE_SIZE         = 100 // MiB
)

type MockedQueryHandler struct {}

var _ types.DataQuerier = MockedQueryHandler{}

func (MockedQueryHandler) Query(request []byte) ([]byte, error) {
	balance := uint256.NewInt(2341).Bytes32()
	nonce := uint256.NewInt(122).Bytes32()

	return proto.Marshal(&ffi.QueryGetAccountResponse{
		Balance: balance[:],
		Nonce: nonce[:],
	})
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

	value := make([]byte, binary.MaxVarintLen32)
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
