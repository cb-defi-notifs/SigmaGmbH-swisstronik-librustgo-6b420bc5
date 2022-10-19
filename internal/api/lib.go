package api

// #include <stdlib.h>
// #include "bindings.h"
import "C"

import (
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

func HelloWorld(name string) error {
	req := ffi.FFIRequest{Req: &ffi.FFIRequest_HelloWorld{HelloWorld: &ffi.Hello{Name: name}}}
	reqBytes, err := proto.Marshal(&req)
	if err != nil {
		log.Fatalln("Failed to encode req:", err)
	}

	d := makeView(reqBytes)
	defer runtime.KeepAlive(reqBytes)
	errmsg := newUnmanagedVector(nil)

	ptr, err := C.make_pb_request(d, &errmsg)
	log.Println(ptr)
	if err != nil {
		return errorWithMessage(err, errmsg)
	}
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
