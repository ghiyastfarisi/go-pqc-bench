package dsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func msg() []byte {
	sh := sha256.Sum256([]byte("PLEASE SIGN THIS DATA!"))
	return sh[:]
}

func signECDSA(sk *ecdsa.PrivateKey) (*big.Int, *big.Int, error) {
	return ecdsa.Sign(rand.Reader, sk, msg())
}

func signEdDSA(sk ed25519.PrivateKey) []byte {
	return ed25519.Sign(sk, msg())
}

func signEdDSA448(sk ed448.PrivateKey) ([]byte, error) {
	return sk.Sign(rand.Reader, msg(), crypto.Hash(0))
}

func signMLDSA44(sk *mldsa44.PrivateKey) ([]byte, error) {
	return sk.Sign(rand.Reader, msg(), crypto.Hash(0))
}

func signMLDSA65(sk *mldsa65.PrivateKey) ([]byte, error) {
	return sk.Sign(rand.Reader, msg(), crypto.Hash(0))
}

func signMLDSA87(sk *mldsa87.PrivateKey) ([]byte, error) {
	return sk.Sign(rand.Reader, msg(), crypto.Hash(0))
}

// Benchmark ECDSA P256 vs Ed25519 vs MLDSA44
func BenchmarkSign1(b *testing.B) {
	// generate the keypair for each
	ECDSASk, _ := generateECDSAKey(elliptic.P256())
	_, EdDSASk, _ := generateEd25519Key()
	_, MLDSA44Sk, _ := generateMLDSA44Key()

	// Sub-benchmark 1: ECDSA-P256
	b.Run("ECDSA-P256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signECDSA(ECDSASk)
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	// Sub-benchmark 2: EdDSA-Ed25519
	b.Run("EdDSA-Ed25519", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signEdDSA(EdDSASk)
		}
		b.ReportAllocs()
	})

	// Sub-benchmark 3: ML-DSA44
	b.Run("ML-DSA44", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signMLDSA44(MLDSA44Sk)
		}
		b.ReportAllocs()
	})
}

func BenchmarkSign2(b *testing.B) {
	// generate the keypair for each
	ECDSASk, _ := generateECDSAKey(elliptic.P384())
	_, EdDSASk, _ := generateEd448Key()
	_, MLDSA65Sk, _ := generateMLDSA65Key()

	// Sub-benchmark 1: ECDSA-P256
	b.Run("ECDSA-384", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signECDSA(ECDSASk)
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	// Sub-benchmark 2: EdDSA-Ed25519
	b.Run("EdDSA-Ed448", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signEdDSA448(EdDSASk)
		}
		b.ReportAllocs()
	})

	// Sub-benchmark 3: ML-DSA44
	b.Run("ML-DSA65", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signMLDSA65(MLDSA65Sk)
		}
		b.ReportAllocs()
	})
}

func BenchmarkSign3(b *testing.B) {
	// generate the keypair for each
	ECDSASk, _ := generateECDSAKey(elliptic.P521())
	_, EdDSASk, _ := generateEd448Key()
	_, MLDSA87Sk, _ := generateMLDSA87Key()

	// Sub-benchmark 1: ECDSA-P256
	b.Run("ECDSA-521", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signECDSA(ECDSASk)
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	// Sub-benchmark 2: EdDSA-Ed25519
	b.Run("EdDSA-Ed448", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signEdDSA448(EdDSASk)
		}
		b.ReportAllocs()
	})

	// Sub-benchmark 3: ML-DSA44
	b.Run("ML-DSA87", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			signMLDSA87(MLDSA87Sk)
		}
		b.ReportAllocs()
	})
}
