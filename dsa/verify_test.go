package dsa

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func verifyECDSA(pk *ecdsa.PublicKey, rBytes, sBytes []byte) bool {
	r, s := new(big.Int).SetBytes(rBytes), new(big.Int).SetBytes(sBytes)
	return ecdsa.Verify(pk, msg(), r, s)
}

func verifyEdDSA(pk ed25519.PublicKey, sig []byte) bool {
	return ed25519.Verify(pk, msg(), sig)
}

func verifyEdDSA448(pk ed448.PublicKey, sig []byte) bool {
	return ed448.Verify(pk, msg(), sig, "")
}

func verifyMLDSA44(pk *mldsa44.PublicKey, sig []byte) bool {
	return mldsa44.Verify(pk, msg(), nil, sig)
}

func verifyMLDSA65(pk *mldsa65.PublicKey, sig []byte) bool {
	return mldsa65.Verify(pk, msg(), nil, sig)
}

func verifyMLDSA87(pk *mldsa87.PublicKey, sig []byte) bool {
	return mldsa87.Verify(pk, msg(), nil, sig)
}

// ==============================
// Benchmark Verification
// ==============================

// Benchmark Verification for ECDSA P256, Ed25519, ML-DSA44
func BenchmarkVerify1(b *testing.B) {
	ECDSASk, _ := generateECDSAKey(elliptic.P256())
	ECDSAPk := &ECDSASk.PublicKey
	ECDSAR, ECDSAS, _ := signECDSA(ECDSASk)

	_, EdDSASk, _ := generateEd25519Key()
	EdDSAPk := EdDSASk.Public().(ed25519.PublicKey)
	EdDSASig := signEdDSA(EdDSASk)

	MLDSA44Pk, MLDSA44Sk, _ := generateMLDSA44Key()
	MLDSA44Sig, _ := signMLDSA44(MLDSA44Sk)

	b.Run("ECDSA-P256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if result := verifyECDSA(ECDSAPk, ECDSAR.Bytes(), ECDSAS.Bytes()); result != true {
				panic("gagal, key tidak sama")
			}
		}
		b.ReportAllocs()
	})

	b.Run("EdDSA-Ed25519", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if result := verifyEdDSA(EdDSAPk, EdDSASig); result != true {
				panic("gagal, key tidak sama")
			}
		}
		b.ReportAllocs()
	})

	b.Run("ML-DSA44", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if result := verifyMLDSA44(MLDSA44Pk, MLDSA44Sig); result != true {
				panic("gagal, key tidak sama")
			}
		}
		b.ReportAllocs()
	})
}

// Benchmark Verification for ECDSA P384, Ed448, ML-DSA65
func BenchmarkVerify2(b *testing.B) {
	ECDSASk, _ := generateECDSAKey(elliptic.P384())
	ECDSAPk := &ECDSASk.PublicKey
	ECDSAR, ECDSAS, _ := signECDSA(ECDSASk)

	EdDSAPk, EdDSASk, _ := generateEd448Key()
	EdDSASign, _ := signEdDSA448(EdDSASk)

	MLDSA65Pk, MLDSA65Sk, _ := generateMLDSA65Key()
	MLDSA65Sig, _ := signMLDSA65(MLDSA65Sk)

	b.Run("ECDSA-384", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			result := verifyECDSA(ECDSAPk, ECDSAR.Bytes(), ECDSAS.Bytes())
			if result != true {
				panic("your key missmatched")
			}
		}
		b.ReportAllocs()
	})

	b.Run("EdDSA-Ed448", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			result := verifyEdDSA448(EdDSAPk, EdDSASign)
			if result != true {
				panic("your key missmatched")
			}
		}
		b.ReportAllocs()
	})

	b.Run("ML-DSA65", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verifyMLDSA65(MLDSA65Pk, MLDSA65Sig)
		}
		b.ReportAllocs()
	})
}

// Benchmark Verification for ECDSA P521, Ed448, ML-DSA87
func BenchmarkVerify3(b *testing.B) {
	ECDSASk, _ := generateECDSAKey(elliptic.P521())
	ECDSAPk := &ECDSASk.PublicKey
	ECDSAR, ECDSAS, _ := signECDSA(ECDSASk)

	EdDSAPk, EdDSASk, _ := generateEd448Key()
	EdDSASign, _ := signEdDSA448(EdDSASk)

	MLDSA87Pk, MLDSA87Sk, _ := generateMLDSA87Key()
	MLDSA87Sig, _ := signMLDSA87(MLDSA87Sk)

	b.Run("ECDSA-521", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verifyECDSA(ECDSAPk, ECDSAR.Bytes(), ECDSAS.Bytes())
		}
		b.ReportAllocs()
	})

	b.Run("EdDSA-Ed448", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verifyEdDSA448(EdDSAPk, EdDSASign)
		}
		b.ReportAllocs()
	})

	b.Run("ML-DSA87", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			verifyMLDSA87(MLDSA87Pk, MLDSA87Sig)
		}
		b.ReportAllocs()
	})
}
