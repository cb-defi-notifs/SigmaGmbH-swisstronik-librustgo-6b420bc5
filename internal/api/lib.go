package api

// #include <stdlib.h>
// #include "bindings.h"
import "C"

import (
	"fmt"
	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	types "github.com/SigmaGmbH/librustgo/types"
	"google.golang.org/protobuf/proto"
	"log"
	"runtime"
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

// Connector is our custom connector
type Connector = types.Connector

// Call handles incoming call to contract or transfer of value
func Call(
	connector Connector,
	from, to, data, value []byte,
	gasLimit uint64,
	txContext *ffi.TransactionContext,
	commit bool,
) (*ffi.HandleTransactionResponse, error) {
	// Construct mocked querier
	c := buildConnector(connector)

	// Create protobuf-encoded transaction data
	params := &ffi.SGXVMCallParams{
		From:     from,
		To:       to,
		Value:    value,
		GasLimit: gasLimit,
		Data:     data,
		Commit:   commit,
	}

	// Create protobuf encoded request
	req := ffi.FFIRequest{Req: &ffi.FFIRequest_CallRequest{
		CallRequest: &ffi.SGXVMCallRequest{
			Params:  params,
			Context: txContext,
		},
	}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
	}

	// Pass request to Rust
	d := makeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := newUnmanagedVector(nil)
	ptr, err := C.make_pb_request(c, d, &errmsg)
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

// Create handles incoming request for creation of new contract
func Create(
	connector Connector,
	from, data, value []byte,
	gasLimit uint64,
	txContext *ffi.TransactionContext,
	commit bool,
) (*ffi.HandleTransactionResponse, error) {
	// Construct mocked querier
	c := buildConnector(connector)

	// Create protobuf-encoded transaction data
	params := &ffi.SGXVMCreateParams{
		From:     from,
		Value:    value,
		GasLimit: gasLimit,
		Data:     data,
		Commit:   commit,
	}

	// Create protobuf encoded request
	req := ffi.FFIRequest{Req: &ffi.FFIRequest_CreateRequest{
		CreateRequest: &ffi.SGXVMCreateRequest{
			Params:  params,
			Context: txContext,
		},
	}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
	}

	// Pass request to Rust
	d := makeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := newUnmanagedVector(nil)
	ptr, err := C.make_pb_request(c, d, &errmsg)
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

// TODO: Remove this function
func Debug(conn Connector) {
	println("lib.go::Debug called")
	c := buildConnector(conn)
	C.debug(c)
}

/**** To error module ***/

func errorWithMessage(err error, b C.UnmanagedVector) error {
	// this checks for out of gas as a special case
	//if errno, ok := err.(syscall.Errno); ok && int(errno) == 2 {
	//	return types.OutOfGasError{}
	//}
	msg := copyAndDestroyUnmanagedVector(b)
	if msg == nil {
		return err
	}
	return fmt.Errorf("%s", string(msg))
}
