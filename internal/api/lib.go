package api

// #include <stdlib.h>
// #include "bindings.h"
import "C"

import (
	"fmt"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"google.golang.org/protobuf/proto"
	"log"
	"runtime"
	"syscall"

	ffi "github.com/SigmaGmbH/librustgo/go_protobuf_gen"
	"github.com/SigmaGmbH/librustgo/types"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
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

// Call handles incoming call to a smart contract or transfer of value
func Call(
	querier DataQuerier,
	from, to, data, value []byte,
	accessList ethtypes.AccessList,
	gasLimit uint64,
	txContext *ffi.TransactionContext,
	commit bool,
) (*ffi.HandleTransactionResponse, error) {
	// Construct mocked querier
	q := buildQuerier(querier)

	// Create protobuf-encoded transaction data
	params := &ffi.SGXVMCallParams{
		From:       from,
		To:         to,
		Data:       data,
		GasLimit:   gasLimit,
		Value:      value,
		AccessList: convertAccessList(accessList),
		Commit:     commit,
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

// Create handles incoming request for creation of a new contract
func Create(
	querier DataQuerier,
	from, data, value []byte,
	accessList ethtypes.AccessList,
	gasLimit uint64,
	txContext *ffi.TransactionContext,
	commit bool,
) (*ffi.HandleTransactionResponse, error) {
	// Construct mocked querier
	q := buildQuerier(querier)

	// Create protobuf-encoded transaction data
	params := &ffi.SGXVMCreateParams{
		From:       from,
		Data:       data,
		GasLimit:   gasLimit,
		Value:      value,
		AccessList: convertAccessList(accessList),
		Commit:     commit,
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

// Converts AccessList type from ethtypes to protobuf-compatible type
func convertAccessList(accessList ethtypes.AccessList) []*ffi.AccessListItem {
	var converted []*ffi.AccessListItem
	for _, item := range accessList {
		accessListItem := &ffi.AccessListItem{
			StorageSlot: convertAccessListStorageSlots(item.StorageKeys),
			Address:     item.Address.Bytes(),
		}

		converted = append(converted, accessListItem)
	}
	return converted
}

// Converts storage slots of access list in [][]byte format
func convertAccessListStorageSlots(slots []ethcommon.Hash) [][]byte {
	var converted [][]byte
	for _, slot := range slots {
		converted = append(converted, slot.Bytes())
	}
	return converted
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
