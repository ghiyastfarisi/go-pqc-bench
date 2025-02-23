package kem

import (
	"crypto/mlkem"
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func generateCirclMLKEM512Key() (*mlkem512.PublicKey, *mlkem512.PrivateKey, error) {
	return mlkem512.GenerateKeyPair(rand.Reader)
}

func generateCirclMLKEM768Key() (*mlkem768.PublicKey, *mlkem768.PrivateKey, error) {
	return mlkem768.GenerateKeyPair(rand.Reader)
}

func generateCirclMLKEM1024Key() (*mlkem1024.PublicKey, *mlkem1024.PrivateKey, error) {
	return mlkem1024.GenerateKeyPair(rand.Reader)
}

func generateMLKEM768Key() (*mlkem.DecapsulationKey768, error) {
	return mlkem.GenerateKey768()
}

func generateMLKEM1024Key() (*mlkem.DecapsulationKey1024, error) {
	return mlkem.GenerateKey1024()
}

func BenchmarkGenKey(b *testing.B) {
	b.Run("CIRCL-MLKEM-512", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := generateCirclMLKEM512Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	b.Run("CIRCL-MLKEM-768", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := generateCirclMLKEM768Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	b.Run("CIRCL-MLKEM-1024", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _, err := generateCirclMLKEM1024Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	b.Run("MLKEM-768", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := generateMLKEM768Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	b.Run("MLKEM-1024", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, err := generateMLKEM1024Key()
			if err != nil {
				b.Fatal(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})
}
