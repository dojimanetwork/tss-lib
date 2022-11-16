// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"

	"github.com/dojimanetwork/tss-lib/v1/common"
	"github.com/dojimanetwork/tss-lib/v1/crypto"
	cmt "github.com/dojimanetwork/tss-lib/v1/crypto/commitments"
	"github.com/dojimanetwork/tss-lib/v1/crypto/vss"
	"github.com/dojimanetwork/tss-lib/v1/crypto/zkp"
	"github.com/dojimanetwork/tss-lib/v1/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-keygen.pb.go

var (
	// Ensure that keygen messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*EDKGRound1Message)(nil),
		(*EDKGRound2Message1)(nil),
		(*EDKGRound2Message2)(nil),
	}
)

// ----- //

func NewEDKGRound1Message(from *tss.PartyID, ct cmt.HashCommitment) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &EDKGRound1Message{
		Commitment: ct.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *EDKGRound1Message) ValidateBasic() bool {
	return m != nil && common.NonEmptyBytes(m.GetCommitment())
}

func (m *EDKGRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewEDKGRound2Message1(
	to, from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		To:          []*tss.PartyID{to},
		IsBroadcast: false,
	}
	content := &EDKGRound2Message1{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *EDKGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.GetShare())
}

func (m *EDKGRound2Message1) UnmarshalShare() *big.Int {
	return new(big.Int).SetBytes(m.Share)
}

// ----- //

func NewEDKGRound2Message2(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *zkp.DLogProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &EDKGRound2Message2{
		DeCommitment: dcBzs,
		ProofAlpha:   proof.Alpha.ToProtobufPoint(),
		ProofT:       proof.T.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *EDKGRound2Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.GetDeCommitment())
}

func (m *EDKGRound2Message2) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *EDKGRound2Message2) UnmarshalZKProof() (*zkp.DLogProof, error) {
	point, err := crypto.NewECPointFromProtobuf(m.GetProofAlpha())
	if err != nil {
		return nil, err
	}
	return &zkp.DLogProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetProofT()),
	}, nil
}
