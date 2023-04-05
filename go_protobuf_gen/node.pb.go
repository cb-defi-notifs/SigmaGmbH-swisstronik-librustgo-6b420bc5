// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.12.4
// source: node.proto

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

type SetupSeedNodeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SetupSeedNodeRequest) Reset() {
	*x = SetupSeedNodeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SetupSeedNodeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetupSeedNodeRequest) ProtoMessage() {}

func (x *SetupSeedNodeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetupSeedNodeRequest.ProtoReflect.Descriptor instead.
func (*SetupSeedNodeRequest) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{0}
}

type SetupSeedNodeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SetupSeedNodeResponse) Reset() {
	*x = SetupSeedNodeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SetupSeedNodeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetupSeedNodeResponse) ProtoMessage() {}

func (x *SetupSeedNodeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetupSeedNodeResponse.ProtoReflect.Descriptor instead.
func (*SetupSeedNodeResponse) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{1}
}

type SetupRegularNodeRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SetupRegularNodeRequest) Reset() {
	*x = SetupRegularNodeRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SetupRegularNodeRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetupRegularNodeRequest) ProtoMessage() {}

func (x *SetupRegularNodeRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetupRegularNodeRequest.ProtoReflect.Descriptor instead.
func (*SetupRegularNodeRequest) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{2}
}

type SetupRegularNodeResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *SetupRegularNodeResponse) Reset() {
	*x = SetupRegularNodeResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SetupRegularNodeResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetupRegularNodeResponse) ProtoMessage() {}

func (x *SetupRegularNodeResponse) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetupRegularNodeResponse.ProtoReflect.Descriptor instead.
func (*SetupRegularNodeResponse) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{3}
}

type CreateAttestationReportRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ApiKey []byte `protobuf:"bytes,1,opt,name=apiKey,proto3" json:"apiKey,omitempty"`
}

func (x *CreateAttestationReportRequest) Reset() {
	*x = CreateAttestationReportRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateAttestationReportRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateAttestationReportRequest) ProtoMessage() {}

func (x *CreateAttestationReportRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateAttestationReportRequest.ProtoReflect.Descriptor instead.
func (*CreateAttestationReportRequest) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{4}
}

func (x *CreateAttestationReportRequest) GetApiKey() []byte {
	if x != nil {
		return x.ApiKey
	}
	return nil
}

type StartSeedServerRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *StartSeedServerRequest) Reset() {
	*x = StartSeedServerRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StartSeedServerRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StartSeedServerRequest) ProtoMessage() {}

func (x *StartSeedServerRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StartSeedServerRequest.ProtoReflect.Descriptor instead.
func (*StartSeedServerRequest) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{5}
}

type StartSeedServerResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *StartSeedServerResponse) Reset() {
	*x = StartSeedServerResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *StartSeedServerResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*StartSeedServerResponse) ProtoMessage() {}

func (x *StartSeedServerResponse) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use StartSeedServerResponse.ProtoReflect.Descriptor instead.
func (*StartSeedServerResponse) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{6}
}

type NodeSeedRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *NodeSeedRequest) Reset() {
	*x = NodeSeedRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NodeSeedRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeSeedRequest) ProtoMessage() {}

func (x *NodeSeedRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeSeedRequest.ProtoReflect.Descriptor instead.
func (*NodeSeedRequest) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{7}
}

type NodeSeedResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *NodeSeedResponse) Reset() {
	*x = NodeSeedResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NodeSeedResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NodeSeedResponse) ProtoMessage() {}

func (x *NodeSeedResponse) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NodeSeedResponse.ProtoReflect.Descriptor instead.
func (*NodeSeedResponse) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{8}
}

type CreateAttestationReportResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *CreateAttestationReportResponse) Reset() {
	*x = CreateAttestationReportResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateAttestationReportResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateAttestationReportResponse) ProtoMessage() {}

func (x *CreateAttestationReportResponse) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateAttestationReportResponse.ProtoReflect.Descriptor instead.
func (*CreateAttestationReportResponse) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{9}
}

type SetupRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Req:
	//	*SetupRequest_SetupSeedNode
	//	*SetupRequest_SetupRegularNode
	//	*SetupRequest_CreateAttestationReport
	//	*SetupRequest_StartSeedServer
	//	*SetupRequest_NodeSeed
	Req isSetupRequest_Req `protobuf_oneof:"req"`
}

func (x *SetupRequest) Reset() {
	*x = SetupRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_node_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SetupRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SetupRequest) ProtoMessage() {}

func (x *SetupRequest) ProtoReflect() protoreflect.Message {
	mi := &file_node_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SetupRequest.ProtoReflect.Descriptor instead.
func (*SetupRequest) Descriptor() ([]byte, []int) {
	return file_node_proto_rawDescGZIP(), []int{10}
}

func (m *SetupRequest) GetReq() isSetupRequest_Req {
	if m != nil {
		return m.Req
	}
	return nil
}

func (x *SetupRequest) GetSetupSeedNode() *SetupSeedNodeRequest {
	if x, ok := x.GetReq().(*SetupRequest_SetupSeedNode); ok {
		return x.SetupSeedNode
	}
	return nil
}

func (x *SetupRequest) GetSetupRegularNode() *SetupRegularNodeRequest {
	if x, ok := x.GetReq().(*SetupRequest_SetupRegularNode); ok {
		return x.SetupRegularNode
	}
	return nil
}

func (x *SetupRequest) GetCreateAttestationReport() *CreateAttestationReportRequest {
	if x, ok := x.GetReq().(*SetupRequest_CreateAttestationReport); ok {
		return x.CreateAttestationReport
	}
	return nil
}

func (x *SetupRequest) GetStartSeedServer() *StartSeedServerRequest {
	if x, ok := x.GetReq().(*SetupRequest_StartSeedServer); ok {
		return x.StartSeedServer
	}
	return nil
}

func (x *SetupRequest) GetNodeSeed() *NodeSeedRequest {
	if x, ok := x.GetReq().(*SetupRequest_NodeSeed); ok {
		return x.NodeSeed
	}
	return nil
}

type isSetupRequest_Req interface {
	isSetupRequest_Req()
}

type SetupRequest_SetupSeedNode struct {
	SetupSeedNode *SetupSeedNodeRequest `protobuf:"bytes,1,opt,name=setupSeedNode,proto3,oneof"`
}

type SetupRequest_SetupRegularNode struct {
	SetupRegularNode *SetupRegularNodeRequest `protobuf:"bytes,2,opt,name=setupRegularNode,proto3,oneof"`
}

type SetupRequest_CreateAttestationReport struct {
	CreateAttestationReport *CreateAttestationReportRequest `protobuf:"bytes,3,opt,name=createAttestationReport,proto3,oneof"`
}

type SetupRequest_StartSeedServer struct {
	StartSeedServer *StartSeedServerRequest `protobuf:"bytes,4,opt,name=startSeedServer,proto3,oneof"`
}

type SetupRequest_NodeSeed struct {
	NodeSeed *NodeSeedRequest `protobuf:"bytes,5,opt,name=nodeSeed,proto3,oneof"`
}

func (*SetupRequest_SetupSeedNode) isSetupRequest_Req() {}

func (*SetupRequest_SetupRegularNode) isSetupRequest_Req() {}

func (*SetupRequest_CreateAttestationReport) isSetupRequest_Req() {}

func (*SetupRequest_StartSeedServer) isSetupRequest_Req() {}

func (*SetupRequest_NodeSeed) isSetupRequest_Req() {}

var File_node_proto protoreflect.FileDescriptor

var file_node_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x6e, 0x6f,
	0x64, 0x65, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x22, 0x16, 0x0a, 0x14, 0x53, 0x65, 0x74, 0x75, 0x70,
	0x53, 0x65, 0x65, 0x64, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x22,
	0x17, 0x0a, 0x15, 0x53, 0x65, 0x74, 0x75, 0x70, 0x53, 0x65, 0x65, 0x64, 0x4e, 0x6f, 0x64, 0x65,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x19, 0x0a, 0x17, 0x53, 0x65, 0x74, 0x75,
	0x70, 0x52, 0x65, 0x67, 0x75, 0x6c, 0x61, 0x72, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x22, 0x1a, 0x0a, 0x18, 0x53, 0x65, 0x74, 0x75, 0x70, 0x52, 0x65, 0x67, 0x75,
	0x6c, 0x61, 0x72, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22,
	0x38, 0x0a, 0x1e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x16, 0x0a, 0x06, 0x61, 0x70, 0x69, 0x4b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x06, 0x61, 0x70, 0x69, 0x4b, 0x65, 0x79, 0x22, 0x18, 0x0a, 0x16, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x53, 0x65, 0x65, 0x64, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x22, 0x19, 0x0a, 0x17, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x65, 0x65, 0x64,
	0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x11,
	0x0a, 0x0f, 0x4e, 0x6f, 0x64, 0x65, 0x53, 0x65, 0x65, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x22, 0x12, 0x0a, 0x10, 0x4e, 0x6f, 0x64, 0x65, 0x53, 0x65, 0x65, 0x64, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x21, 0x0a, 0x1f, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41,
	0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0xa0, 0x03, 0x0a, 0x0c, 0x53, 0x65, 0x74,
	0x75, 0x70, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x47, 0x0a, 0x0d, 0x73, 0x65, 0x74,
	0x75, 0x70, 0x53, 0x65, 0x65, 0x64, 0x4e, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1f, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x53, 0x65, 0x74,
	0x75, 0x70, 0x53, 0x65, 0x65, 0x64, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x48, 0x00, 0x52, 0x0d, 0x73, 0x65, 0x74, 0x75, 0x70, 0x53, 0x65, 0x65, 0x64, 0x4e, 0x6f,
	0x64, 0x65, 0x12, 0x50, 0x0a, 0x10, 0x73, 0x65, 0x74, 0x75, 0x70, 0x52, 0x65, 0x67, 0x75, 0x6c,
	0x61, 0x72, 0x4e, 0x6f, 0x64, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x6e,
	0x6f, 0x64, 0x65, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x53, 0x65, 0x74, 0x75, 0x70, 0x52, 0x65,
	0x67, 0x75, 0x6c, 0x61, 0x72, 0x4e, 0x6f, 0x64, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x48, 0x00, 0x52, 0x10, 0x73, 0x65, 0x74, 0x75, 0x70, 0x52, 0x65, 0x67, 0x75, 0x6c, 0x61, 0x72,
	0x4e, 0x6f, 0x64, 0x65, 0x12, 0x65, 0x0a, 0x17, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x74,
	0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x6e, 0x6f, 0x64,
	0x65, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x48, 0x00, 0x52, 0x17, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x4d, 0x0a, 0x0f, 0x73,
	0x74, 0x61, 0x72, 0x74, 0x53, 0x65, 0x65, 0x64, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x6e, 0x6f, 0x64, 0x65,
	0x2e, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x65, 0x65, 0x64, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x0f, 0x73, 0x74, 0x61, 0x72, 0x74,
	0x53, 0x65, 0x65, 0x64, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x12, 0x38, 0x0a, 0x08, 0x6e, 0x6f,
	0x64, 0x65, 0x53, 0x65, 0x65, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x6e,
	0x6f, 0x64, 0x65, 0x2e, 0x6e, 0x6f, 0x64, 0x65, 0x2e, 0x4e, 0x6f, 0x64, 0x65, 0x53, 0x65, 0x65,
	0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x48, 0x00, 0x52, 0x08, 0x6e, 0x6f, 0x64, 0x65,
	0x53, 0x65, 0x65, 0x64, 0x42, 0x05, 0x0a, 0x03, 0x72, 0x65, 0x71, 0x42, 0x04, 0x5a, 0x02, 0x2e,
	0x2f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_node_proto_rawDescOnce sync.Once
	file_node_proto_rawDescData = file_node_proto_rawDesc
)

func file_node_proto_rawDescGZIP() []byte {
	file_node_proto_rawDescOnce.Do(func() {
		file_node_proto_rawDescData = protoimpl.X.CompressGZIP(file_node_proto_rawDescData)
	})
	return file_node_proto_rawDescData
}

var file_node_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_node_proto_goTypes = []interface{}{
	(*SetupSeedNodeRequest)(nil),            // 0: node.node.SetupSeedNodeRequest
	(*SetupSeedNodeResponse)(nil),           // 1: node.node.SetupSeedNodeResponse
	(*SetupRegularNodeRequest)(nil),         // 2: node.node.SetupRegularNodeRequest
	(*SetupRegularNodeResponse)(nil),        // 3: node.node.SetupRegularNodeResponse
	(*CreateAttestationReportRequest)(nil),  // 4: node.node.CreateAttestationReportRequest
	(*StartSeedServerRequest)(nil),          // 5: node.node.StartSeedServerRequest
	(*StartSeedServerResponse)(nil),         // 6: node.node.StartSeedServerResponse
	(*NodeSeedRequest)(nil),                 // 7: node.node.NodeSeedRequest
	(*NodeSeedResponse)(nil),                // 8: node.node.NodeSeedResponse
	(*CreateAttestationReportResponse)(nil), // 9: node.node.CreateAttestationReportResponse
	(*SetupRequest)(nil),                    // 10: node.node.SetupRequest
}
var file_node_proto_depIdxs = []int32{
	0, // 0: node.node.SetupRequest.setupSeedNode:type_name -> node.node.SetupSeedNodeRequest
	2, // 1: node.node.SetupRequest.setupRegularNode:type_name -> node.node.SetupRegularNodeRequest
	4, // 2: node.node.SetupRequest.createAttestationReport:type_name -> node.node.CreateAttestationReportRequest
	5, // 3: node.node.SetupRequest.startSeedServer:type_name -> node.node.StartSeedServerRequest
	7, // 4: node.node.SetupRequest.nodeSeed:type_name -> node.node.NodeSeedRequest
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_node_proto_init() }
func file_node_proto_init() {
	if File_node_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_node_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SetupSeedNodeRequest); i {
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
		file_node_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SetupSeedNodeResponse); i {
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
		file_node_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SetupRegularNodeRequest); i {
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
		file_node_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SetupRegularNodeResponse); i {
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
		file_node_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateAttestationReportRequest); i {
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
		file_node_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StartSeedServerRequest); i {
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
		file_node_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*StartSeedServerResponse); i {
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
		file_node_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NodeSeedRequest); i {
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
		file_node_proto_msgTypes[8].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NodeSeedResponse); i {
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
		file_node_proto_msgTypes[9].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateAttestationReportResponse); i {
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
		file_node_proto_msgTypes[10].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SetupRequest); i {
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
	file_node_proto_msgTypes[10].OneofWrappers = []interface{}{
		(*SetupRequest_SetupSeedNode)(nil),
		(*SetupRequest_SetupRegularNode)(nil),
		(*SetupRequest_CreateAttestationReport)(nil),
		(*SetupRequest_StartSeedServer)(nil),
		(*SetupRequest_NodeSeed)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_node_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_node_proto_goTypes,
		DependencyIndexes: file_node_proto_depIdxs,
		MessageInfos:      file_node_proto_msgTypes,
	}.Build()
	File_node_proto = out.File
	file_node_proto_rawDesc = nil
	file_node_proto_goTypes = nil
	file_node_proto_depIdxs = nil
}
