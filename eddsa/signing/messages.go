// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/dojimanetwork/tss-lib/v1/common"
	"github.com/dojimanetwork/tss-lib/v1/crypto"
	cmt "github.com/dojimanetwork/tss-lib/v1/crypto/commitments"
	"github.com/dojimanetwork/tss-lib/v1/crypto/zkp"
	"github.com/dojimanetwork/tss-lib/v1/tss"
)

// These messages were generated from Protocol Buffers definitions into eddsa-signing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*EDSignRound1Message)(nil),
		(*EDSignRound2Message)(nil),
		(*EDSignRound3Message)(nil),
	}
)

// ----- //

func NewEDSignRound1Message(
	from *tss.PartyID,
	commitment cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &EDSignRound1Message{
		Commitment: commitment.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *EDSignRound1Message) ValidateBasic() bool {
	return m.Commitment != nil &&
		common.NonEmptyBytes(m.GetCommitment())
}

func (m *EDSignRound1Message) UnmarshalCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetCommitment())
}

// ----- //

func NewEDSignRound2Message(
	from *tss.PartyID,
	deCommitment cmt.HashDeCommitment,
	proof *zkp.DLogProof,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	dcBzs := common.BigIntsToBytes(deCommitment)
	content := &EDSignRound2Message{
		DeCommitment: dcBzs,
		ProofAlpha:   proof.Alpha.ToProtobufPoint(),
		ProofT:       proof.T.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *EDSignRound2Message) ValidateBasic() bool {
	return m != nil &&
		m.ProofAlpha != nil &&
		common.NonEmptyMultiBytes(m.DeCommitment, 3) &&
		m.ProofAlpha.ValidateBasic() &&
		common.NonEmptyBytes(m.ProofT)
}

func (m *EDSignRound2Message) UnmarshalDeCommitment() []*big.Int {
	deComBzs := m.GetDeCommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

func (m *EDSignRound2Message) UnmarshalZKProof() (*zkp.DLogProof, error) {
	point, err := crypto.NewECPointFromProtobuf(m.GetProofAlpha())
	if err != nil {
		return nil, err
	}
	return &zkp.DLogProof{
		Alpha: point,
		T:     new(big.Int).SetBytes(m.GetProofT()),
	}, nil
}

// ----- //

func NewEDSignRound3Message(
	from *tss.PartyID,
	si *big.Int,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	content := &EDSignRound3Message{
		S: si.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *EDSignRound3Message) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.S)
}

func (m *EDSignRound3Message) UnmarshalS() *big.Int {
	return new(big.Int).SetBytes(m.S)
}
