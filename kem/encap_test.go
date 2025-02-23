package kem

import (
	"crypto/mlkem"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func encapCirclMLKEM768(pk *mlkem768.PublicKey) ([]byte, []byte) {
	sharedKey := make([]byte, mlkem768.SharedKeySize)
	cipherText := make([]byte, mlkem768.CiphertextSize)

	pk.EncapsulateTo(cipherText, sharedKey, nil)

	return cipherText, sharedKey
}

func encapCirclMLKEM1024(pk *mlkem1024.PublicKey) ([]byte, []byte) {
	sharedKey := make([]byte, mlkem1024.SharedKeySize)
	cipherText := make([]byte, mlkem1024.CiphertextSize)

	pk.EncapsulateTo(cipherText, sharedKey, nil)

	return cipherText, sharedKey
}

func encapMLKEM768(pk *mlkem.EncapsulationKey768) ([]byte, []byte) {
	sharedKey, cipherText := pk.Encapsulate()

	return cipherText, sharedKey
}

func encapMLKEM1024(pk *mlkem.EncapsulationKey1024) ([]byte, []byte) {
	sharedKey, cipherText := pk.Encapsulate()

	return cipherText, sharedKey
}

func BenchmarkEncap(b *testing.B) {
	pkCirclMLKEM768, _, _ := generateCirclMLKEM768Key()
	b.Run("CIRCL-MLKEM-768", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encapCirclMLKEM768(pkCirclMLKEM768)
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	pkCirclMLKEM1024, _, _ := generateCirclMLKEM1024Key()
	b.Run("CIRCL-MLKEM-1024", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encapCirclMLKEM1024(pkCirclMLKEM1024)
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	dkMLKEM768, _ := generateMLKEM768Key()
	b.Run("MLKEM-768", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encapMLKEM768(dkMLKEM768.EncapsulationKey())
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	dkMLKEM1024, _ := generateMLKEM1024Key()
	b.Run("MLKEM-1024", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			encapMLKEM1024(dkMLKEM1024.EncapsulationKey())
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})
}
