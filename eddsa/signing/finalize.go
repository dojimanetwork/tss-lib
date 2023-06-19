// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	crypto_ed25519 "crypto/ed25519"
	"errors"
	"fmt"
	"math/big"

	"github.com/agl/ed25519/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"

	"github.com/dojimanetwork/tss-lib/common"
	"github.com/dojimanetwork/tss-lib/tss"
)

func (round *finalization) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 4
	round.started = true
	round.resetOK()

	sumS := round.temp.si
	for j := range round.Parties().IDs() {
		round.ok[j] = true
		if j == round.PartyID().Index {
			continue
		}
		r3msg := round.temp.signRound3Messages[j].Content().(*EDSignRound3Message)
		sjBytes := bigIntToEncodedBytes(r3msg.UnmarshalS())
		var tmpSumS [32]byte
		edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), sjBytes)
		sumS = &tmpSumS
	}
	s := encodedBytesToBigInt(sumS)

	fullSig := append(bigIntToEncodedBytes(round.temp.r)[:], sumS[:]...)
	// save the signature for final output
	signature := new(common.ECSignature)
	signature.Signature = fullSig
	signature.R = round.temp.r.Bytes()
	signature.S = s.Bytes()
	signature.M = round.temp.m.Bytes()
	round.data.Signature = signature

	pk := edwards.PublicKey{
		Curve: tss.EC(),
		X:     round.key.EDDSAPub.X(),
		Y:     round.key.EDDSAPub.Y(),
	}
	msg_v := round.temp.m.Bytes()
	dcrec_ok := edwards.Verify(&pk, msg_v, round.temp.r, s)
	crypto_ok := crypto_ed25519.Verify(pk.SerializeUncompressed(), msg_v, fullSig)
	if !dcrec_ok && !crypto_ok {
		return round.WrapError(fmt.Errorf("signature verification failed"))
	}
	round.end <- round.data

	return nil
}

func (round *finalization) CanAccept(msg tss.ParsedMessage) bool {
	// not expecting any incoming messages in this round
	return false
}

func (round *finalization) Update() (bool, *tss.Error) {
	// not expecting any incoming messages in this round
	return false, nil
}

func (round *finalization) NextRound() tss.Round {
	return nil // finished!
}
