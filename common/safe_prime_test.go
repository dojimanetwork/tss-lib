// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"fmt"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_getSafePrime(t *testing.T) {
	prime := new(big.Int).SetInt64(80000)
	sPrime := getSafePrime(prime)
	fmt.Println("prime", prime, "safeprime", sPrime)
	assert.True(t, sPrime.ProbablyPrime(50))
}

func Test_getSafePrime_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	assert.False(t, sPrime.ProbablyPrime(50))
}

func Test_Validate(t *testing.T) {
	prime := new(big.Int).SetInt64(5)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.True(t, sgp.Validate())
}

func Test_Validate_Bad(t *testing.T) {
	prime := new(big.Int).SetInt64(12)
	sPrime := getSafePrime(prime)
	sgp := &GermainSafePrime{prime, sPrime}
	assert.False(t, sgp.Validate())
}

func TestGetRandomGermainPrimeConcurrent(t *testing.T) {
	sgps, err := GetRandomSafePrimesConcurrent(2048, 2, 20*time.Minute, runtime.NumCPU())
	fmt.Println(sgps[0].Prime().String())
	assert.NoError(t, err)
	assert.Equal(t, 2, len(sgps))
	for _, sgp := range sgps {
		assert.NotNil(t, sgp)
		assert.True(t, sgp.Validate())
	}
}
