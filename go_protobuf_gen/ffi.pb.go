// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.19.4
// source: ffi.proto

package __

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AccessListItem struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StorageSlot [][]byte `protobuf:"bytes,1,rep,name=storageSlot,proto3" json:"storageSlot,omitempty"`
}

func (x *AccessListItem) Reset() {
	*x = AccessListItem{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ffi_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessListItem) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessListItem) ProtoMessage() {}

func (x *AccessListItem) ProtoReflect() protoreflect.Message {
	mi := &file_ffi_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessListItem.ProtoReflect.Descriptor instead.
func (*AccessListItem) Descriptor() ([]byte, []int) {
	return file_ffi_proto_rawDescGZIP(), []int{0}
}

func (x *AccessListItem) GetStorageSlot() [][]byte {
	if x != nil {
		return x.StorageSlot
	}
	return nil
}

type TransactionData struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	From                 []byte                     `protobuf:"bytes,1,opt,name=from,proto3" json:"from,omitempty"`
	To                   []byte                     `protobuf:"bytes,2,opt,name=to,proto3" json:"to,omitempty"`
	Data                 []byte                     `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
	Nonce                []byte                     `protobuf:"bytes,4,opt,name=nonce,proto3" json:"nonce,omitempty"`
	GasLimit             []byte                     `protobuf:"bytes,5,opt,name=gasLimit,proto3" json:"gasLimit,omitempty"`
	GasPrice             []byte                     `protobuf:"bytes,6,opt,name=gasPrice,proto3,oneof" json:"gasPrice,omitempty"`
	MaxFeePerGas         []byte                     `protobuf:"bytes,7,opt,name=maxFeePerGas,proto3,oneof" json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas []byte                     `protobuf:"bytes,8,opt,name=maxPriorityFeePerGas,proto3,oneof" json:"maxPriorityFeePerGas,omitempty"`
	Value                []byte                     `protobuf:"bytes,9,opt,name=value,proto3" json:"value,omitempty"`
	ChainId              *uint64                    `protobuf:"varint,10,opt,name=chainId,proto3,oneof" json:"chainId,omitempty"`
	AccessList           map[string]*AccessListItem `protobuf:"bytes,11,rep,name=accessList,proto3" json:"accessList,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"` // Usage of string is workaround to use [u8; 32] as key in a map
}

func (x *TransactionData) Reset() {
	*x = TransactionData{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ffi_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *TransactionData) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*TransactionData) ProtoMessage() {}

func (x *TransactionData) ProtoReflect() protoreflect.Message {
	mi := &file_ffi_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use TransactionData.ProtoReflect.Descriptor instead.
func (*TransactionData) Descriptor() ([]byte, []int) {
	return file_ffi_proto_rawDescGZIP(), []int{1}
}

func (x *TransactionData) GetFrom() []byte {
	if x != nil {
		return x.From
	}
	return nil
}

func (x *TransactionData) GetTo() []byte {
	if x != nil {
		return x.To
	}
	return nil
}

func (x *TransactionData) GetData() []byte {
	if x != nil {
		return x.Data
	}
	return nil
}

func (x *TransactionData) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

func (x *TransactionData) GetGasLimit() []byte {
	if x != nil {
		return x.GasLimit
	}
	return nil
}

func (x *TransactionData) GetGasPrice() []byte {
	if x != nil {
		return x.GasPrice
	}
	return nil
}

func (x *TransactionData) GetMaxFeePerGas() []byte {
	if x != nil {
		return x.MaxFeePerGas
	}
	return nil
}

func (x *TransactionData) GetMaxPriorityFeePerGas() []byte {
	if x != nil {
		return x.MaxPriorityFeePerGas
	}
	return nil
}

func (x *TransactionData) GetValue() []byte {
	if x != nil {
		return x.Value
	}
	return nil
}

func (x *TransactionData) GetChainId() uint64 {
	if x != nil && x.ChainId != nil {
		return *x.ChainId
	}
	return 0
}

func (x *TransactionData) GetAccessList() map[string]*AccessListItem {
	if x != nil {
		return x.AccessList
	}
	return nil
}

type HandleTransactionResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Hash string `protobuf:"bytes,1,opt,name=hash,proto3" json:"hash,omitempty"`
}

func (x *HandleTransactionResponse) Reset() {
	*x = HandleTransactionResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ffi_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HandleTransactionResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HandleTransactionResponse) ProtoMessage() {}

func (x *HandleTransactionResponse) ProtoReflect() protoreflect.Message {
	mi := &file_ffi_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HandleTransactionResponse.ProtoReflect.Descriptor instead.
func (*HandleTransactionResponse) Descriptor() ([]byte, []int) {
	return file_ffi_proto_rawDescGZIP(), []int{2}
}

func (x *HandleTransactionResponse) GetHash() string {
	if x != nil {
		return x.Hash
	}
	return ""
}

type FFIRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Req:
	//
	//	*FFIRequest_HandleTransaction
	Req isFFIRequest_Req `protobuf_oneof:"req"`
}

func (x *FFIRequest) Reset() {
	*x = FFIRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_ffi_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FFIRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FFIRequest) ProtoMessage() {}

func (x *FFIRequest) ProtoReflect() protoreflect.Message {
	mi := &file_ffi_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FFIRequest.ProtoReflect.Descriptor instead.
func (*FFIRequest) Descriptor() ([]byte, []int) {
	return file_ffi_proto_rawDescGZIP(), []int{3}
}

func (m *FFIRequest) GetReq() isFFIRequest_Req {
	if m != nil {
		return m.Req
	}
	return nil
}

func (x *FFIRequest) GetHandleTransaction() *TransactionData {
	if x, ok := x.GetReq().(*FFIRequest_HandleTransaction); ok {
		return x.HandleTransaction
	}
	return nil
}

type isFFIRequest_Req interface {
	isFFIRequest_Req()
}

type FFIRequest_HandleTransaction struct {
	HandleTransaction *TransactionData `protobuf:"bytes,1,opt,name=handleTransaction,proto3,oneof"`
}

func (*FFIRequest_HandleTransaction) isFFIRequest_Req() {}

var File_ffi_proto protoreflect.FileDescriptor

var file_ffi_proto_rawDesc = []byte{
	0x0a, 0x09, 0x66, 0x66, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x07, 0x66, 0x66, 0x69,
	0x2e, 0x66, 0x66, 0x69, 0x22, 0x32, 0x0a, 0x0e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69,
	0x73, 0x74, 0x49, 0x74, 0x65, 0x6d, 0x12, 0x20, 0x0a, 0x0b, 0x73, 0x74, 0x6f, 0x72, 0x61, 0x67,
	0x65, 0x53, 0x6c, 0x6f, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0b, 0x73, 0x74, 0x6f,
	0x72, 0x61, 0x67, 0x65, 0x53, 0x6c, 0x6f, 0x74, 0x22, 0x98, 0x04, 0x0a, 0x0f, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x61, 0x74, 0x61, 0x12, 0x12, 0x0a, 0x04,
	0x66, 0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04, 0x66, 0x72, 0x6f, 0x6d,
	0x12, 0x0e, 0x0a, 0x02, 0x74, 0x6f, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x74, 0x6f,
	0x12, 0x12, 0x0a, 0x04, 0x64, 0x61, 0x74, 0x61, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x04,
	0x64, 0x61, 0x74, 0x61, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x67, 0x61,
	0x73, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x08, 0x67, 0x61,
	0x73, 0x4c, 0x69, 0x6d, 0x69, 0x74, 0x12, 0x1f, 0x0a, 0x08, 0x67, 0x61, 0x73, 0x50, 0x72, 0x69,
	0x63, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x00, 0x52, 0x08, 0x67, 0x61, 0x73, 0x50,
	0x72, 0x69, 0x63, 0x65, 0x88, 0x01, 0x01, 0x12, 0x27, 0x0a, 0x0c, 0x6d, 0x61, 0x78, 0x46, 0x65,
	0x65, 0x50, 0x65, 0x72, 0x47, 0x61, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x01, 0x52,
	0x0c, 0x6d, 0x61, 0x78, 0x46, 0x65, 0x65, 0x50, 0x65, 0x72, 0x47, 0x61, 0x73, 0x88, 0x01, 0x01,
	0x12, 0x37, 0x0a, 0x14, 0x6d, 0x61, 0x78, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x46,
	0x65, 0x65, 0x50, 0x65, 0x72, 0x47, 0x61, 0x73, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0c, 0x48, 0x02,
	0x52, 0x14, 0x6d, 0x61, 0x78, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x46, 0x65, 0x65,
	0x50, 0x65, 0x72, 0x47, 0x61, 0x73, 0x88, 0x01, 0x01, 0x12, 0x14, 0x0a, 0x05, 0x76, 0x61, 0x6c,
	0x75, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12,
	0x1d, 0x0a, 0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x64, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x04,
	0x48, 0x03, 0x52, 0x07, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x49, 0x64, 0x88, 0x01, 0x01, 0x12, 0x48,
	0x0a, 0x0a, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x18, 0x0b, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x28, 0x2e, 0x66, 0x66, 0x69, 0x2e, 0x66, 0x66, 0x69, 0x2e, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x44, 0x61, 0x74, 0x61, 0x2e, 0x41, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x0a, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x1a, 0x56, 0x0a, 0x0f, 0x41, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x4c, 0x69, 0x73, 0x74, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b,
	0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x2d, 0x0a,
	0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x17, 0x2e, 0x66,
	0x66, 0x69, 0x2e, 0x66, 0x66, 0x69, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c, 0x69, 0x73,
	0x74, 0x49, 0x74, 0x65, 0x6d, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01,
	0x42, 0x0b, 0x0a, 0x09, 0x5f, 0x67, 0x61, 0x73, 0x50, 0x72, 0x69, 0x63, 0x65, 0x42, 0x0f, 0x0a,
	0x0d, 0x5f, 0x6d, 0x61, 0x78, 0x46, 0x65, 0x65, 0x50, 0x65, 0x72, 0x47, 0x61, 0x73, 0x42, 0x17,
	0x0a, 0x15, 0x5f, 0x6d, 0x61, 0x78, 0x50, 0x72, 0x69, 0x6f, 0x72, 0x69, 0x74, 0x79, 0x46, 0x65,
	0x65, 0x50, 0x65, 0x72, 0x47, 0x61, 0x73, 0x42, 0x0a, 0x0a, 0x08, 0x5f, 0x63, 0x68, 0x61, 0x69,
	0x6e, 0x49, 0x64, 0x22, 0x2f, 0x0a, 0x19, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x54, 0x72, 0x61,
	0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x12, 0x0a, 0x04, 0x68, 0x61, 0x73, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04,
	0x68, 0x61, 0x73, 0x68, 0x22, 0x5d, 0x0a, 0x0a, 0x46, 0x46, 0x49, 0x52, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x12, 0x48, 0x0a, 0x11, 0x68, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x54, 0x72, 0x61, 0x6e,
	0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e,
	0x66, 0x66, 0x69, 0x2e, 0x66, 0x66, 0x69, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74,
	0x69, 0x6f, 0x6e, 0x44, 0x61, 0x74, 0x61, 0x48, 0x00, 0x52, 0x11, 0x68, 0x61, 0x6e, 0x64, 0x6c,
	0x65, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x05, 0x0a, 0x03,
	0x72, 0x65, 0x71, 0x42, 0x04, 0x5a, 0x02, 0x2e, 0x2f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_ffi_proto_rawDescOnce sync.Once
	file_ffi_proto_rawDescData = file_ffi_proto_rawDesc
)

func file_ffi_proto_rawDescGZIP() []byte {
	file_ffi_proto_rawDescOnce.Do(func() {
		file_ffi_proto_rawDescData = protoimpl.X.CompressGZIP(file_ffi_proto_rawDescData)
	})
	return file_ffi_proto_rawDescData
}

var file_ffi_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_ffi_proto_goTypes = []interface{}{
	(*AccessListItem)(nil),            // 0: ffi.ffi.AccessListItem
	(*TransactionData)(nil),           // 1: ffi.ffi.TransactionData
	(*HandleTransactionResponse)(nil), // 2: ffi.ffi.HandleTransactionResponse
	(*FFIRequest)(nil),                // 3: ffi.ffi.FFIRequest
	nil,                               // 4: ffi.ffi.TransactionData.AccessListEntry
}
var file_ffi_proto_depIdxs = []int32{
	4, // 0: ffi.ffi.TransactionData.accessList:type_name -> ffi.ffi.TransactionData.AccessListEntry
	1, // 1: ffi.ffi.FFIRequest.handleTransaction:type_name -> ffi.ffi.TransactionData
	0, // 2: ffi.ffi.TransactionData.AccessListEntry.value:type_name -> ffi.ffi.AccessListItem
	3, // [3:3] is the sub-list for method output_type
	3, // [3:3] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_ffi_proto_init() }
func file_ffi_proto_init() {
	if File_ffi_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_ffi_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessListItem); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ffi_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*TransactionData); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ffi_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HandleTransactionResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_ffi_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FFIRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_ffi_proto_msgTypes[1].OneofWrappers = []interface{}{}
	file_ffi_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*FFIRequest_HandleTransaction)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_ffi_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_ffi_proto_goTypes,
		DependencyIndexes: file_ffi_proto_depIdxs,
		MessageInfos:      file_ffi_proto_msgTypes,
	}.Build()
	File_ffi_proto = out.File
	file_ffi_proto_rawDesc = nil
	file_ffi_proto_goTypes = nil
	file_ffi_proto_depIdxs = nil
}
