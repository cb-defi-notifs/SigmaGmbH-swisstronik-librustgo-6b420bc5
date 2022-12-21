package api

// #include <stdlib.h>
// #include "bindings.h"
import "C"

import (
	"fmt"
	"google.golang.org/protobuf/proto"                      
	"log"
	"runtime"
	"syscall"

	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	types "github.com/SigmaGmbH/librustgo/types"
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

type Querier = types.Querier

// Our custom querier
type DataQuerier = types.DataQuerier

// Handles incoming ethereum transaction
func HandleTx(querier DataQuerier, from, to, data, value []byte, gasLimit uint64) (*ffi.HandleTransactionResponse, error) {
	// Construct mocked querier
	q := buildQuerier(querier)

	// Create protobuf encoded request
	req := ffi.FFIRequest{Req: &ffi.FFIRequest_HandleTransaction{HandleTransaction: &ffi.TransactionData{
		From:     from,
		To:       to,
		Value:    value,
		GasLimit: gasLimit,
		Data: data,
	}}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
	}

	// Pass request to Rust
	d := makeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := newUnmanagedVector(nil)
	ptr, err := C.make_pb_request(q, d, &errmsg)
	if err != nil {
		return &ffi.HandleTransactionResponse{}, errorWithMessage(err, errmsg)
	}

	// Recover returned value
	executionResult := copyAndDestroyUnmanagedVector(ptr)
	response := ffi.HandleTransactionResponse{}
	if err := proto.Unmarshal(executionResult, &response); err != nil {
		log.Fatalln("Failed to decode execution result:", err)
	}

	return &response, nil
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
