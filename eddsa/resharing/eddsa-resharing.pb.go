// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: protob/eddsa-resharing.proto

package resharing

import (
	common "github.com/dojimanetwork/tss-lib/common"
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

//
// The Round 1 data is broadcast to peers of the New Committee in this message.
type EDDGRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EddsaPub    *common.ECPoint `protobuf:"bytes,1,opt,name=eddsa_pub,json=eddsaPub,proto3" json:"eddsa_pub,omitempty"`
	VCommitment []byte          `protobuf:"bytes,2,opt,name=v_commitment,json=vCommitment,proto3" json:"v_commitment,omitempty"`
}

func (x *EDDGRound1Message) Reset() {
	*x = EDDGRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_eddsa_resharing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EDDGRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EDDGRound1Message) ProtoMessage() {}

func (x *EDDGRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_eddsa_resharing_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EDDGRound1Message.ProtoReflect.Descriptor instead.
func (*EDDGRound1Message) Descriptor() ([]byte, []int) {
	return file_protob_eddsa_resharing_proto_rawDescGZIP(), []int{0}
}

func (x *EDDGRound1Message) GetEddsaPub() *common.ECPoint {
	if x != nil {
		return x.EddsaPub
	}
	return nil
}

func (x *EDDGRound1Message) GetVCommitment() []byte {
	if x != nil {
		return x.VCommitment
	}
	return nil
}

//
// The Round 2 "ACK" is broadcast to peers of the Old Committee in this message.
type EDDGRound2Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EDDGRound2Message) Reset() {
	*x = EDDGRound2Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_eddsa_resharing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EDDGRound2Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EDDGRound2Message) ProtoMessage() {}

func (x *EDDGRound2Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_eddsa_resharing_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EDDGRound2Message.ProtoReflect.Descriptor instead.
func (*EDDGRound2Message) Descriptor() ([]byte, []int) {
	return file_protob_eddsa_resharing_proto_rawDescGZIP(), []int{1}
}

//
// The Round 3 data is sent to peers of the New Committee in this message.
type EDDGRound3Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Share []byte `protobuf:"bytes,1,opt,name=share,proto3" json:"share,omitempty"`
}

func (x *EDDGRound3Message1) Reset() {
	*x = EDDGRound3Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_eddsa_resharing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EDDGRound3Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EDDGRound3Message1) ProtoMessage() {}

func (x *EDDGRound3Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_eddsa_resharing_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EDDGRound3Message1.ProtoReflect.Descriptor instead.
func (*EDDGRound3Message1) Descriptor() ([]byte, []int) {
	return file_protob_eddsa_resharing_proto_rawDescGZIP(), []int{2}
}

func (x *EDDGRound3Message1) GetShare() []byte {
	if x != nil {
		return x.Share
	}
	return nil
}

//
// The Round 3 data is broadcast to peers of the New Committee in this message.
type EDDGRound3Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	VDecommitment [][]byte `protobuf:"bytes,1,rep,name=v_decommitment,json=vDecommitment,proto3" json:"v_decommitment,omitempty"`
}

func (x *EDDGRound3Message2) Reset() {
	*x = EDDGRound3Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_eddsa_resharing_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EDDGRound3Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EDDGRound3Message2) ProtoMessage() {}

func (x *EDDGRound3Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_eddsa_resharing_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EDDGRound3Message2.ProtoReflect.Descriptor instead.
func (*EDDGRound3Message2) Descriptor() ([]byte, []int) {
	return file_protob_eddsa_resharing_proto_rawDescGZIP(), []int{3}
}

func (x *EDDGRound3Message2) GetVDecommitment() [][]byte {
	if x != nil {
		return x.VDecommitment
	}
	return nil
}

//
// The Round 4 "ACK" is broadcast to peers of the Old and New Committees from the New Committee in this message.
type EDDGRound4Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EDDGRound4Message) Reset() {
	*x = EDDGRound4Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_eddsa_resharing_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EDDGRound4Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EDDGRound4Message) ProtoMessage() {}

func (x *EDDGRound4Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_eddsa_resharing_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EDDGRound4Message.ProtoReflect.Descriptor instead.
func (*EDDGRound4Message) Descriptor() ([]byte, []int) {
	return file_protob_eddsa_resharing_proto_rawDescGZIP(), []int{4}
}

var File_protob_eddsa_resharing_proto protoreflect.FileDescriptor

var file_protob_eddsa_resharing_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x64, 0x64, 0x73, 0x61, 0x2d, 0x72,
	0x65, 0x73, 0x68, 0x61, 0x72, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x13,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x5d, 0x0a, 0x11, 0x45, 0x44, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x25, 0x0a, 0x09, 0x65, 0x64, 0x64, 0x73,
	0x61, 0x5f, 0x70, 0x75, 0x62, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43,
	0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x08, 0x65, 0x64, 0x64, 0x73, 0x61, 0x50, 0x75, 0x62, 0x12,
	0x21, 0x0a, 0x0c, 0x76, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x76, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x22, 0x13, 0x0a, 0x11, 0x45, 0x44, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x32,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x22, 0x2a, 0x0a, 0x12, 0x45, 0x44, 0x44, 0x47, 0x52,
	0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x14, 0x0a,
	0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x73, 0x68,
	0x61, 0x72, 0x65, 0x22, 0x3b, 0x0a, 0x12, 0x45, 0x44, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x25, 0x0a, 0x0e, 0x76, 0x5f, 0x64,
	0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0c, 0x52, 0x0d, 0x76, 0x44, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74,
	0x22, 0x13, 0x0a, 0x11, 0x45, 0x44, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x34, 0x4d, 0x65,
	0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x32, 0x5a, 0x30, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e,
	0x63, 0x6f, 0x6d, 0x2f, 0x64, 0x6f, 0x6a, 0x69, 0x6d, 0x61, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72,
	0x6b, 0x2f, 0x74, 0x73, 0x73, 0x2d, 0x6c, 0x69, 0x62, 0x2f, 0x65, 0x64, 0x64, 0x73, 0x61, 0x2f,
	0x72, 0x65, 0x73, 0x68, 0x61, 0x72, 0x69, 0x6e, 0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_protob_eddsa_resharing_proto_rawDescOnce sync.Once
	file_protob_eddsa_resharing_proto_rawDescData = file_protob_eddsa_resharing_proto_rawDesc
)

func file_protob_eddsa_resharing_proto_rawDescGZIP() []byte {
	file_protob_eddsa_resharing_proto_rawDescOnce.Do(func() {
		file_protob_eddsa_resharing_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_eddsa_resharing_proto_rawDescData)
	})
	return file_protob_eddsa_resharing_proto_rawDescData
}

var file_protob_eddsa_resharing_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_protob_eddsa_resharing_proto_goTypes = []interface{}{
	(*EDDGRound1Message)(nil),  // 0: EDDGRound1Message
	(*EDDGRound2Message)(nil),  // 1: EDDGRound2Message
	(*EDDGRound3Message1)(nil), // 2: EDDGRound3Message1
	(*EDDGRound3Message2)(nil), // 3: EDDGRound3Message2
	(*EDDGRound4Message)(nil),  // 4: EDDGRound4Message
	(*common.ECPoint)(nil),     // 5: ECPoint
}
var file_protob_eddsa_resharing_proto_depIdxs = []int32{
	5, // 0: EDDGRound1Message.eddsa_pub:type_name -> ECPoint
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_protob_eddsa_resharing_proto_init() }
func file_protob_eddsa_resharing_proto_init() {
	if File_protob_eddsa_resharing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_eddsa_resharing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EDDGRound1Message); i {
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
		file_protob_eddsa_resharing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EDDGRound2Message); i {
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
		file_protob_eddsa_resharing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EDDGRound3Message1); i {
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
		file_protob_eddsa_resharing_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EDDGRound3Message2); i {
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
		file_protob_eddsa_resharing_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EDDGRound4Message); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protob_eddsa_resharing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_eddsa_resharing_proto_goTypes,
		DependencyIndexes: file_protob_eddsa_resharing_proto_depIdxs,
		MessageInfos:      file_protob_eddsa_resharing_proto_msgTypes,
	}.Build()
	File_protob_eddsa_resharing_proto = out.File
	file_protob_eddsa_resharing_proto_rawDesc = nil
	file_protob_eddsa_resharing_proto_goTypes = nil
	file_protob_eddsa_resharing_proto_depIdxs = nil
}
