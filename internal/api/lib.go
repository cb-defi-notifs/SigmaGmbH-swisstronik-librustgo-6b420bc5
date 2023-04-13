package api

// #include <stdlib.h>
// #include "bindings.h"
import "C"

import (
	"fmt"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"golang.org/x/net/netutil"
	"google.golang.org/protobuf/proto"
	"log"
	"net"
	"runtime"

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

// Connector is our custom connector
type Connector = types.Connector

// IsNodeInitialized checks if node was initialized and master key was sealed
func IsNodeInitialized() (bool, error) {
	// Create protobuf encoded request
	req := ffi.SetupRequest{Req: &ffi.SetupRequest_IsInitialized{
		IsInitialized: &ffi.IsInitializedRequest{},
	}}

	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
		return false, err
	}

	// Pass request to Rust
	d := MakeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := NewUnmanagedVector(nil)

	ptr, err := C.handle_initialization_request(d, &errmsg)
	if err != nil {
		return false, ErrorWithMessage(err, errmsg)
	}

	// Recover returned value
	executionResult := CopyAndDestroyUnmanagedVector(ptr)
	response := ffi.IsInitializedResponse{}
	if err := proto.Unmarshal(executionResult, &response); err != nil {
		log.Fatalln("Failed to decode execution result:", err)
		return false, err
	}

	return response.IsInitialized, nil
}

// SetupSeedNode handles initialization of seed node which will share seed with other nodes
func SetupSeedNode() error {
	// Create protobuf encoded request
	req := ffi.SetupRequest{Req: &ffi.SetupRequest_SetupSeedNode{
		SetupSeedNode: &ffi.SetupSeedNodeRequest{},
	}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
		return err
	}

	// Pass request to Rust
	d := MakeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := NewUnmanagedVector(nil)
	_, err = C.handle_initialization_request(d, &errmsg)
	if err != nil {
		return ErrorWithMessage(err, errmsg)
	}

	return nil
}

// SetupRegularNode handles initialization of regular node which will request seed from seed node
func SetupRegularNode() {
	// Create protobuf encoded request
	req := ffi.SetupRequest{Req: &ffi.SetupRequest_SetupRegularNode{
		SetupRegularNode: &ffi.SetupRegularNodeRequest{},
	}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
	}

	// Pass request to Rust
	d := MakeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := NewUnmanagedVector(nil)

	_ = C.handle_initialization_request(d, &errmsg)
}

func CreateAttestationReport(apiKey []byte) {
	if len(apiKey) != 32 {
		log.Fatalln("Wrong api key size")
		return
	}

	// Create protobuf encoded request
	req := ffi.SetupRequest{Req: &ffi.SetupRequest_CreateAttestationReport{
		CreateAttestationReport: &ffi.CreateAttestationReportRequest{
			ApiKey: apiKey,
		},
	}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
	}

	// Pass request to Rust
	d := MakeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := NewUnmanagedVector(nil)

	_ = C.handle_initialization_request(d, &errmsg)
}

// StartSeedServer handles initialization of seed server
func StartSeedServer(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Println("[Seed Server] Cannot start seed server")
		return err
	}

	go func() {
		for {
			connection, err := ln.Accept()
			if err != nil {
				fmt.Println("[Seed Server] Got error ", err.Error(), ", connection: ", connection.RemoteAddr().String())
				continue
			}

			if err := attestPeer(connection); err != nil {
				fmt.Println("[Seed Server] Attestation failed. Reason: {:?}", err)
				continue
			}
		}
	}()

	fmt.Println("[Seed Server] Starting seed server. Address: ", addr)

	return nil
}

func attestPeer(connection net.Conn) error {
	defer connection.Close()
	println("[Seed Server] Attesting peer: ", connection.RemoteAddr().String())

	// Extract file descriptor for socket
	file, err := connection.(*net.TCPConn).File()
	if err != nil {
		fmt.Println("[Seed Server] Cannot get access to the connection. Reason: ", err.Error())
		return err
	}

	// Create protobuf encoded request
	req := ffi.SetupRequest{Req: &ffi.SetupRequest_StartSeedServer{
		StartSeedServer: &ffi.StartSeedServerRequest{
			Fd: int32(file.Fd()),
		},
	}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		fmt.Println("[Seed Server] Failed to encode req:", err)
		return err
	}

	// Pass request to Rust
	d := MakeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := NewUnmanagedVector(nil)
	_, err = C.handle_initialization_request(d, &errmsg)
	if err != nil {
		return ErrorWithMessage(err, errmsg)
	}

	return nil
}

// Listen starts a net.Listener on the tcp network on the given address.
// If there is a specified MaxOpenConnections in the config, it will also set the limitListener.
func Listen(addr string, maxOpenConnections int) (net.Listener, error) {
	if addr == "" {
		addr = ":http"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	if maxOpenConnections > 0 {
		ln = netutil.LimitListener(ln, maxOpenConnections)
	}
	return ln, err
}

// RequestSeed handles request of seed from seed server
func RequestSeed(addr string) error {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("Cannot establish connection with seed server. Reason: ", err.Error())
		return err
	}

	file, err := conn.(*net.TCPConn).File()
	if err != nil {
		fmt.Println("Cannot get access to the connection. Reason: ", err.Error())
		return err
	}

	// Create protobuf encoded request
	req := ffi.SetupRequest{Req: &ffi.SetupRequest_NodeSeed{
		NodeSeed: &ffi.NodeSeedRequest{
			Fd: int32(file.Fd()),
		},
	}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
		return err
	}

	// Pass request to Rust
	d := MakeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := NewUnmanagedVector(nil)
	_, err = C.handle_initialization_request(d, &errmsg)
	if err != nil {
		return ErrorWithMessage(err, errmsg)
	}

	return nil
}

// Call handles incoming call to contract or transfer of value
func Call(
	connector Connector,
	from, to, data, value []byte,
	accessList ethtypes.AccessList,
	gasLimit uint64,
	txContext *ffi.TransactionContext,
	commit bool,
) (*ffi.HandleTransactionResponse, error) {
	// Construct mocked querier
	c := BuildConnector(connector)

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
	d := MakeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := NewUnmanagedVector(nil)
	ptr, err := C.make_pb_request(c, d, &errmsg)
	if err != nil {
		return &ffi.HandleTransactionResponse{}, ErrorWithMessage(err, errmsg)
	}

	// Recover returned value
	executionResult := CopyAndDestroyUnmanagedVector(ptr)
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
	accessList ethtypes.AccessList,
	gasLimit uint64,
	txContext *ffi.TransactionContext,
	commit bool,
) (*ffi.HandleTransactionResponse, error) {
	// Construct mocked querier
	c := BuildConnector(connector)

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
	d := MakeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)

	errmsg := NewUnmanagedVector(nil)
	ptr, err := C.make_pb_request(c, d, &errmsg)
	if err != nil {
		return &ffi.HandleTransactionResponse{}, ErrorWithMessage(err, errmsg)
	}

	// Recover returned value
	executionResult := CopyAndDestroyUnmanagedVector(ptr)
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

func ErrorWithMessage(err error, b C.UnmanagedVector) error {
	msg := CopyAndDestroyUnmanagedVector(b)
	if msg == nil {
		return err
	}
	return fmt.Errorf("%s", string(msg))
}
