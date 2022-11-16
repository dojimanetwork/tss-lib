// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"math/big"

	"github.com/dojimanetwork/tss-lib/v1/common"
	"github.com/dojimanetwork/tss-lib/v1/crypto"
	cmt "github.com/dojimanetwork/tss-lib/v1/crypto/commitments"
	"github.com/dojimanetwork/tss-lib/v1/crypto/dlnp"
	"github.com/dojimanetwork/tss-lib/v1/crypto/paillier"
	"github.com/dojimanetwork/tss-lib/v1/crypto/vss"
	"github.com/dojimanetwork/tss-lib/v1/tss"
)

// These messages were generated from Protocol Buffers definitions into ecdsa-resharing.pb.go

var (
	// Ensure that signing messages implement ValidateBasic
	_ = []tss.MessageContent{
		(*ECDGRound1Message)(nil),
		(*ECDGRound2Message1)(nil),
		(*ECDGRound2Message2)(nil),
		(*ECDGRound3Message1)(nil),
		(*ECDGRound3Message2)(nil),
	}
)

// ----- //

func NewECDGRound1Message(
	to []*tss.PartyID,
	from *tss.PartyID,
	ecdsaPub *crypto.ECPoint,
	vct cmt.HashCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	content := &ECDGRound1Message{
		EcdsaPub:    ecdsaPub.ToProtobufPoint(),
		VCommitment: vct.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *ECDGRound1Message) ValidateBasic() bool {
	return m != nil &&
		m.EcdsaPub != nil &&
		m.EcdsaPub.ValidateBasic() &&
		common.NonEmptyBytes(m.VCommitment)
}

func (m *ECDGRound1Message) UnmarshalECDSAPub() (*crypto.ECPoint, error) {
	return crypto.NewECPointFromProtobuf(m.GetEcdsaPub())
}

func (m *ECDGRound1Message) UnmarshalVCommitment() *big.Int {
	return new(big.Int).SetBytes(m.GetVCommitment())
}

// ----- //

func NewECDGRound2Message1(
	to []*tss.PartyID,
	from *tss.PartyID,
	paillierPK *paillier.PublicKey,
	paillierPf paillier.Proof,
	NTildei, H1i, H2i *big.Int,
	dlnProof1, dlnProof2 *dlnp.Proof,
) (tss.ParsedMessage, error) {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	paiPfBzs := common.BigIntsToBytes(paillierPf[:])
	dlnProof1Bz, err := dlnProof1.Marshal()
	if err != nil {
		return nil, err
	}
	dlnProof2Bz, err := dlnProof2.Marshal()
	if err != nil {
		return nil, err
	}
	content := &ECDGRound2Message1{
		PaillierN:     paillierPK.N.Bytes(),
		PaillierProof: paiPfBzs,
		NTilde:        NTildei.Bytes(),
		H1:            H1i.Bytes(),
		H2:            H2i.Bytes(),
		Dlnproof_1:    dlnProof1Bz,
		Dlnproof_2:    dlnProof2Bz,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg), nil
}

func (m *ECDGRound2Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.PaillierProof) &&
		common.NonEmptyBytes(m.PaillierN) &&
		common.NonEmptyBytes(m.NTilde) &&
		common.NonEmptyBytes(m.H1) &&
		common.NonEmptyBytes(m.H2) &&
		// expected len of dln proof = sizeof(int64) + len(alpha) + len(t)
		common.NonEmptyMultiBytes(m.GetDlnproof_1(), 2+(dlnp.Iterations*2)) &&
		common.NonEmptyMultiBytes(m.GetDlnproof_2(), 2+(dlnp.Iterations*2))
}

func (m *ECDGRound2Message1) UnmarshalPaillierPK() *paillier.PublicKey {
	return &paillier.PublicKey{
		N: new(big.Int).SetBytes(m.PaillierN),
	}
}

func (m *ECDGRound2Message1) UnmarshalNTilde() *big.Int {
	return new(big.Int).SetBytes(m.GetNTilde())
}

func (m *ECDGRound2Message1) UnmarshalH1() *big.Int {
	return new(big.Int).SetBytes(m.GetH1())
}

func (m *ECDGRound2Message1) UnmarshalH2() *big.Int {
	return new(big.Int).SetBytes(m.GetH2())
}

func (m *ECDGRound2Message1) UnmarshalPaillierProof() paillier.Proof {
	var pf paillier.Proof
	ints := common.ByteSlicesToBigInts(m.PaillierProof)
	copy(pf[:], ints[:paillier.ProofIters])
	return pf
}

func (m *ECDGRound2Message1) UnmarshalDLNProof1() (*dlnp.Proof, error) {
	return dlnp.UnmarshalProof(m.GetDlnproof_1())
}

func (m *ECDGRound2Message1) UnmarshalDLNProof2() (*dlnp.Proof, error) {
	return dlnp.UnmarshalProof(m.GetDlnproof_2())
}

// ----- //

func NewECDGRound2Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: true,
	}
	content := &ECDGRound2Message2{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *ECDGRound2Message2) ValidateBasic() bool {
	return true
}

// ----- //

func NewECDGRound3Message1(
	to *tss.PartyID,
	from *tss.PartyID,
	share *vss.Share,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               []*tss.PartyID{to},
		IsBroadcast:      false,
		IsToOldCommittee: false,
	}
	content := &ECDGRound3Message1{
		Share: share.Share.Bytes(),
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *ECDGRound3Message1) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyBytes(m.Share)
}

// ----- //

func NewECDGRound3Message2(
	to []*tss.PartyID,
	from *tss.PartyID,
	vdct cmt.HashDeCommitment,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:             from,
		To:               to,
		IsBroadcast:      true,
		IsToOldCommittee: false,
	}
	vDctBzs := common.BigIntsToBytes(vdct)
	content := &ECDGRound3Message2{
		VDecommitment: vDctBzs,
	}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *ECDGRound3Message2) ValidateBasic() bool {
	return m != nil &&
		common.NonEmptyMultiBytes(m.VDecommitment)
}

func (m *ECDGRound3Message2) UnmarshalVDeCommitment() cmt.HashDeCommitment {
	deComBzs := m.GetVDecommitment()
	return cmt.NewHashDeCommitmentFromBytes(deComBzs)
}

// ----- //

func NewECDGRound4Message(
	to []*tss.PartyID,
	from *tss.PartyID,
) tss.ParsedMessage {
	meta := tss.MessageRouting{
		From:                    from,
		To:                      to,
		IsBroadcast:             true,
		IsToOldAndNewCommittees: true,
	}
	content := &ECDGRound4Message{}
	msg := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, msg)
}

func (m *ECDGRound4Message) ValidateBasic() bool {
	return true
}
