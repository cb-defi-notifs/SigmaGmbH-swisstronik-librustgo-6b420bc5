package api

// #include <stdlib.h>
// #include "bindings.h"
import "C"

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/golang/protobuf/proto"
	"log"
	"runtime"
	"syscall"

	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	"github.com/SigmaGmbH/librustgo/types"
)

// Value types
type (
	cint   = C.int
	cbool  = C.bool
	cusize = C.size_t
	cu8    = C.uint8_t
	cu32   = C.uint32_t
	cu64   = C.uint64_t
	ci8    = C.int8_t
	ci32   = C.int32_t
	ci64   = C.int64_t
)

// Pointers
type cu8_ptr = *C.uint8_t

func HandleTx() error {
	// Create sample execution data
	from, decodingErr := hex.DecodeString("91e1f4Bb1C1895F6c65cD8379DE1323A8bF3Cf7c")
	if decodingErr != nil {
		log.Fatalln("Failed to decode address:", decodingErr)
	}
	to, decodingErr := hex.DecodeString("91b126ff9AF242408090A223829Eb88A61724AA5")
	if decodingErr != nil {
		log.Fatalln("Failed to decode address:", decodingErr)
	}

	// Create protobuf encoded request
	req := ffi.FFIRequest{Req: &ffi.FFIRequest_HandleTransaction{HandleTransaction: &ffi.TransactionData{
		From:     from,
		To:       to,
		Value:    make([]byte, binary.MaxVarintLen32),
		GasLimit: make([]byte, binary.MaxVarintLen32),
	}}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
	}

	// Pass request to Rust
	d := makeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := newUnmanagedVector(nil)
	ptr, err := C.make_pb_request(d, &errmsg)
	if err != nil {
		return errorWithMessage(err, errmsg)
	}

	// Recover returned value
	data := copyAndDestroyUnmanagedVector(ptr)
	response := ffi.HandleTransactionResponse{}
	if err := proto.Unmarshal(data, &response); err != nil {
		log.Fatalln("Failed to decode result:", err)
	}

	println(response.Hash)

	return nil
}

/**** To error module ***/

func errorWithMessage(err error, b C.UnmanagedVector) error {
	// this checks for out of gas as a special case
	if errno, ok := err.(syscall.Errno); ok && int(errno) == 2 {
		return types.OutOfGasError{}
	}
	msg := copyAndDestroyUnmanagedVector(b)
	if msg == nil {
		return err
	}
	return fmt.Errorf("%s", string(msg))
}
