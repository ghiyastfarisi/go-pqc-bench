package dsa

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"strconv"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

// Function to get the iteration count from ENV variable
func getIterationCount() int {
	iterStr := os.Getenv("BENCH_ITER")
	if iterStr == "" {
		return 100 // Default iterations
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter <= 0 {
		fmt.Println("Invalid BENCH_ITER value, using default (100)")
		return 100
	}
	return iter
}

// Key generation functions
func generateECDSAKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func generateEd25519Key() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func generateEd448Key() (ed448.PublicKey, ed448.PrivateKey, error) {
	return ed448.GenerateKey(rand.Reader)
}

// ML-DSA key generation for different variants
func generateMLDSA44Key() (*mldsa44.PublicKey, *mldsa44.PrivateKey, error) {
	return mldsa44.GenerateKey(rand.Reader)
}

func generateMLDSA65Key() (*mldsa65.PublicKey, *mldsa65.PrivateKey, error) {
	return mldsa65.GenerateKey(rand.Reader)
}

func generateMLDSA87Key() (*mldsa87.PublicKey, *mldsa87.PrivateKey, error) {
	return mldsa87.GenerateKey(rand.Reader)
}

// Benchmark ECDSA P256 vs Ed25519 vs MLDSA44
func BenchmarkGenKey1(b *testing.B) {
	// Sub-benchmark 1: ECDSA-P256
	b.Run("ECDSA-P256", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := generateECDSAKey(elliptic.P256())
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	// Sub-benchmark 2: EdDSA-Ed25519
	b.Run("EdDSA-Ed25519", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := generateEd25519Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})

	// Sub-benchmark 3: ML-DSA44
	b.Run("ML-DSA44", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := generateMLDSA44Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})
}

func BenchmarkGenKey2(b *testing.B) {
	// Sub-benchmark 1: ECDSA-P384
	b.Run("ECDSA-P384", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := generateECDSAKey(elliptic.P384())
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	// Sub-benchmark 2: EdDSA-Ed448
	b.Run("EdDSA-Ed448", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := generateEd448Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})

	// Sub-benchmark 3: ML-DSA65
	b.Run("ML-DSA65", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := generateMLDSA65Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})
}

func BenchmarkGenKey3(b *testing.B) {
	// Sub-benchmark 1: ECDSA-P521
	b.Run("ECDSA-P521", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := generateECDSAKey(elliptic.P521())
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	// Sub-benchmark 2: EdDSA-Ed448
	b.Run("EdDSA-Ed448", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := generateEd448Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})

	// Sub-benchmark 3: ML-DSA65
	b.Run("ML-DSA87", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := generateMLDSA87Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs()
	})
}
