// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.19.4
// source: protob/ecdsa-resharing.proto

package resharing

import (
	common "github.com/dojimanetwork/tss-lib/v1/common"
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
type ECDGRound1Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EcdsaPub    *common.ECPoint `protobuf:"bytes,1,opt,name=ecdsa_pub,json=ecdsaPub,proto3" json:"ecdsa_pub,omitempty"`
	VCommitment []byte          `protobuf:"bytes,2,opt,name=v_commitment,json=vCommitment,proto3" json:"v_commitment,omitempty"`
}

func (x *ECDGRound1Message) Reset() {
	*x = ECDGRound1Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECDGRound1Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECDGRound1Message) ProtoMessage() {}

func (x *ECDGRound1Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECDGRound1Message.ProtoReflect.Descriptor instead.
func (*ECDGRound1Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{0}
}

func (x *ECDGRound1Message) GetEcdsaPub() *common.ECPoint {
	if x != nil {
		return x.EcdsaPub
	}
	return nil
}

func (x *ECDGRound1Message) GetVCommitment() []byte {
	if x != nil {
		return x.VCommitment
	}
	return nil
}

//
// The Round 2 data is broadcast to other peers of the New Committee in this message.
type ECDGRound2Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PaillierN     []byte   `protobuf:"bytes,1,opt,name=paillier_n,json=paillierN,proto3" json:"paillier_n,omitempty"`
	PaillierProof [][]byte `protobuf:"bytes,2,rep,name=paillier_proof,json=paillierProof,proto3" json:"paillier_proof,omitempty"`
	NTilde        []byte   `protobuf:"bytes,3,opt,name=n_tilde,json=nTilde,proto3" json:"n_tilde,omitempty"`
	H1            []byte   `protobuf:"bytes,4,opt,name=h1,proto3" json:"h1,omitempty"`
	H2            []byte   `protobuf:"bytes,5,opt,name=h2,proto3" json:"h2,omitempty"`
	Dlnproof_1    [][]byte `protobuf:"bytes,6,rep,name=dlnproof_1,json=dlnproof1,proto3" json:"dlnproof_1,omitempty"`
	Dlnproof_2    [][]byte `protobuf:"bytes,7,rep,name=dlnproof_2,json=dlnproof2,proto3" json:"dlnproof_2,omitempty"`
}

func (x *ECDGRound2Message1) Reset() {
	*x = ECDGRound2Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECDGRound2Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECDGRound2Message1) ProtoMessage() {}

func (x *ECDGRound2Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECDGRound2Message1.ProtoReflect.Descriptor instead.
func (*ECDGRound2Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{1}
}

func (x *ECDGRound2Message1) GetPaillierN() []byte {
	if x != nil {
		return x.PaillierN
	}
	return nil
}

func (x *ECDGRound2Message1) GetPaillierProof() [][]byte {
	if x != nil {
		return x.PaillierProof
	}
	return nil
}

func (x *ECDGRound2Message1) GetNTilde() []byte {
	if x != nil {
		return x.NTilde
	}
	return nil
}

func (x *ECDGRound2Message1) GetH1() []byte {
	if x != nil {
		return x.H1
	}
	return nil
}

func (x *ECDGRound2Message1) GetH2() []byte {
	if x != nil {
		return x.H2
	}
	return nil
}

func (x *ECDGRound2Message1) GetDlnproof_1() [][]byte {
	if x != nil {
		return x.Dlnproof_1
	}
	return nil
}

func (x *ECDGRound2Message1) GetDlnproof_2() [][]byte {
	if x != nil {
		return x.Dlnproof_2
	}
	return nil
}

//
// The Round 2 "ACK" is broadcast to peers of the Old Committee in this message.
type ECDGRound2Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ECDGRound2Message2) Reset() {
	*x = ECDGRound2Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECDGRound2Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECDGRound2Message2) ProtoMessage() {}

func (x *ECDGRound2Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECDGRound2Message2.ProtoReflect.Descriptor instead.
func (*ECDGRound2Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{2}
}

//
// The Round 3 data is sent to peers of the New Committee in this message.
type ECDGRound3Message1 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Share []byte `protobuf:"bytes,1,opt,name=share,proto3" json:"share,omitempty"`
}

func (x *ECDGRound3Message1) Reset() {
	*x = ECDGRound3Message1{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECDGRound3Message1) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECDGRound3Message1) ProtoMessage() {}

func (x *ECDGRound3Message1) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECDGRound3Message1.ProtoReflect.Descriptor instead.
func (*ECDGRound3Message1) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{3}
}

func (x *ECDGRound3Message1) GetShare() []byte {
	if x != nil {
		return x.Share
	}
	return nil
}

//
// The Round 3 data is broadcast to peers of the New Committee in this message.
type ECDGRound3Message2 struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	VDecommitment [][]byte `protobuf:"bytes,1,rep,name=v_decommitment,json=vDecommitment,proto3" json:"v_decommitment,omitempty"`
}

func (x *ECDGRound3Message2) Reset() {
	*x = ECDGRound3Message2{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECDGRound3Message2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECDGRound3Message2) ProtoMessage() {}

func (x *ECDGRound3Message2) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECDGRound3Message2.ProtoReflect.Descriptor instead.
func (*ECDGRound3Message2) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{4}
}

func (x *ECDGRound3Message2) GetVDecommitment() [][]byte {
	if x != nil {
		return x.VDecommitment
	}
	return nil
}

//
// The Round 4 "ACK" is broadcast to peers of the Old and New Committees from the New Committee in this message.
type ECDGRound4Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *ECDGRound4Message) Reset() {
	*x = ECDGRound4Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_ecdsa_resharing_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECDGRound4Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECDGRound4Message) ProtoMessage() {}

func (x *ECDGRound4Message) ProtoReflect() protoreflect.Message {
	mi := &file_protob_ecdsa_resharing_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECDGRound4Message.ProtoReflect.Descriptor instead.
func (*ECDGRound4Message) Descriptor() ([]byte, []int) {
	return file_protob_ecdsa_resharing_proto_rawDescGZIP(), []int{5}
}

var File_protob_ecdsa_resharing_proto protoreflect.FileDescriptor

var file_protob_ecdsa_resharing_proto_rawDesc = []byte{
	0x0a, 0x1c, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2d, 0x72,
	0x65, 0x73, 0x68, 0x61, 0x72, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x13,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x22, 0x5d, 0x0a, 0x11, 0x45, 0x43, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x31, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x25, 0x0a, 0x09, 0x65, 0x63, 0x64, 0x73,
	0x61, 0x5f, 0x70, 0x75, 0x62, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x08, 0x2e, 0x45, 0x43,
	0x50, 0x6f, 0x69, 0x6e, 0x74, 0x52, 0x08, 0x65, 0x63, 0x64, 0x73, 0x61, 0x50, 0x75, 0x62, 0x12,
	0x21, 0x0a, 0x0c, 0x76, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x76, 0x43, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65,
	0x6e, 0x74, 0x22, 0xd1, 0x01, 0x0a, 0x12, 0x45, 0x43, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64,
	0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x31, 0x12, 0x1d, 0x0a, 0x0a, 0x70, 0x61, 0x69,
	0x6c, 0x6c, 0x69, 0x65, 0x72, 0x5f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x09, 0x70,
	0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x4e, 0x12, 0x25, 0x0a, 0x0e, 0x70, 0x61, 0x69, 0x6c,
	0x6c, 0x69, 0x65, 0x72, 0x5f, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0c,
	0x52, 0x0d, 0x70, 0x61, 0x69, 0x6c, 0x6c, 0x69, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x6f, 0x66, 0x12,
	0x17, 0x0a, 0x07, 0x6e, 0x5f, 0x74, 0x69, 0x6c, 0x64, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x06, 0x6e, 0x54, 0x69, 0x6c, 0x64, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x68, 0x31, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x68, 0x31, 0x12, 0x0e, 0x0a, 0x02, 0x68, 0x32, 0x18, 0x05,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x02, 0x68, 0x32, 0x12, 0x1d, 0x0a, 0x0a, 0x64, 0x6c, 0x6e, 0x70,
	0x72, 0x6f, 0x6f, 0x66, 0x5f, 0x31, 0x18, 0x06, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x64, 0x6c,
	0x6e, 0x70, 0x72, 0x6f, 0x6f, 0x66, 0x31, 0x12, 0x1d, 0x0a, 0x0a, 0x64, 0x6c, 0x6e, 0x70, 0x72,
	0x6f, 0x6f, 0x66, 0x5f, 0x32, 0x18, 0x07, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x09, 0x64, 0x6c, 0x6e,
	0x70, 0x72, 0x6f, 0x6f, 0x66, 0x32, 0x22, 0x14, 0x0a, 0x12, 0x45, 0x43, 0x44, 0x47, 0x52, 0x6f,
	0x75, 0x6e, 0x64, 0x32, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x22, 0x2a, 0x0a, 0x12,
	0x45, 0x43, 0x44, 0x47, 0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x31, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x05, 0x73, 0x68, 0x61, 0x72, 0x65, 0x22, 0x3b, 0x0a, 0x12, 0x45, 0x43, 0x44, 0x47,
	0x52, 0x6f, 0x75, 0x6e, 0x64, 0x33, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x32, 0x12, 0x25,
	0x0a, 0x0e, 0x76, 0x5f, 0x64, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x69, 0x74, 0x6d, 0x65, 0x6e, 0x74,
	0x18, 0x01, 0x20, 0x03, 0x28, 0x0c, 0x52, 0x0d, 0x76, 0x44, 0x65, 0x63, 0x6f, 0x6d, 0x6d, 0x69,
	0x74, 0x6d, 0x65, 0x6e, 0x74, 0x22, 0x13, 0x0a, 0x11, 0x45, 0x43, 0x44, 0x47, 0x52, 0x6f, 0x75,
	0x6e, 0x64, 0x34, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x35, 0x5a, 0x33, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64, 0x6f, 0x6a, 0x69, 0x6d, 0x61, 0x6e,
	0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x74, 0x73, 0x73, 0x2d, 0x6c, 0x69, 0x62, 0x2f, 0x76,
	0x31, 0x2f, 0x65, 0x63, 0x64, 0x73, 0x61, 0x2f, 0x72, 0x65, 0x73, 0x68, 0x61, 0x72, 0x69, 0x6e,
	0x67, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_ecdsa_resharing_proto_rawDescOnce sync.Once
	file_protob_ecdsa_resharing_proto_rawDescData = file_protob_ecdsa_resharing_proto_rawDesc
)

func file_protob_ecdsa_resharing_proto_rawDescGZIP() []byte {
	file_protob_ecdsa_resharing_proto_rawDescOnce.Do(func() {
		file_protob_ecdsa_resharing_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_ecdsa_resharing_proto_rawDescData)
	})
	return file_protob_ecdsa_resharing_proto_rawDescData
}

var file_protob_ecdsa_resharing_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_protob_ecdsa_resharing_proto_goTypes = []interface{}{
	(*ECDGRound1Message)(nil),  // 0: ECDGRound1Message
	(*ECDGRound2Message1)(nil), // 1: ECDGRound2Message1
	(*ECDGRound2Message2)(nil), // 2: ECDGRound2Message2
	(*ECDGRound3Message1)(nil), // 3: ECDGRound3Message1
	(*ECDGRound3Message2)(nil), // 4: ECDGRound3Message2
	(*ECDGRound4Message)(nil),  // 5: ECDGRound4Message
	(*common.ECPoint)(nil),     // 6: ECPoint
}
var file_protob_ecdsa_resharing_proto_depIdxs = []int32{
	6, // 0: ECDGRound1Message.ecdsa_pub:type_name -> ECPoint
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_protob_ecdsa_resharing_proto_init() }
func file_protob_ecdsa_resharing_proto_init() {
	if File_protob_ecdsa_resharing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_ecdsa_resharing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECDGRound1Message); i {
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
		file_protob_ecdsa_resharing_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECDGRound2Message1); i {
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
		file_protob_ecdsa_resharing_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECDGRound2Message2); i {
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
		file_protob_ecdsa_resharing_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECDGRound3Message1); i {
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
		file_protob_ecdsa_resharing_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECDGRound3Message2); i {
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
		file_protob_ecdsa_resharing_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECDGRound4Message); i {
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
			RawDescriptor: file_protob_ecdsa_resharing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_ecdsa_resharing_proto_goTypes,
		DependencyIndexes: file_protob_ecdsa_resharing_proto_depIdxs,
		MessageInfos:      file_protob_ecdsa_resharing_proto_msgTypes,
	}.Build()
	File_protob_ecdsa_resharing_proto = out.File
	file_protob_ecdsa_resharing_proto_rawDesc = nil
	file_protob_ecdsa_resharing_proto_goTypes = nil
	file_protob_ecdsa_resharing_proto_depIdxs = nil
}
