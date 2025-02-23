package kem

import (
	"bytes"
	"crypto/mlkem"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

func decapCirclMLKEM768(sk *mlkem768.PrivateKey, sharedSecret, cipherText []byte) error {
	ss := make([]byte, mlkem768.SharedKeySize)

	sk.DecapsulateTo(ss, cipherText)
	if !bytes.Equal(ss, sharedSecret) {
		return fmt.Errorf("invalid")
	}

	return nil
}

func decapCirclMLKEM1024(sk *mlkem1024.PrivateKey, sharedSecret, cipherText []byte) error {
	ss := make([]byte, mlkem1024.SharedKeySize)

	sk.DecapsulateTo(ss, cipherText)
	if !bytes.Equal(ss, sharedSecret) {
		return fmt.Errorf("invalid")
	}

	return nil
}

func decapMLKEM768(sk *mlkem.DecapsulationKey768, ss, ct []byte) error {
	sharedKey, err := sk.Decapsulate(ct)
	if err != nil {
		return err
	}

	if !bytes.Equal(ss, sharedKey) {
		return fmt.Errorf("invalid")
	}

	return nil
}

func decapMLKEM1024(sk *mlkem.DecapsulationKey1024, ss, ct []byte) error {
	sharedKey, err := sk.Decapsulate(ct)
	if err != nil {
		return err
	}

	if !bytes.Equal(ss, sharedKey) {
		return fmt.Errorf("invalid")
	}

	return nil
}

func BenchmarkDecap(b *testing.B) {
	pkCirclMLKEM768, skCirclMLKEM768, _ := generateCirclMLKEM768Key()
	ct, ss := encapCirclMLKEM768(pkCirclMLKEM768)
	b.Run("CIRCL-MLKEM-768", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := decapCirclMLKEM768(skCirclMLKEM768, ss, ct); err != nil {
				panic(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	pkCirclMLKEM1024, skCirclMLKEM1024, _ := generateCirclMLKEM1024Key()
	ct1, ss1 := encapCirclMLKEM1024(pkCirclMLKEM1024)
	b.Run("CIRCL-MLKEM-1024", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := decapCirclMLKEM1024(skCirclMLKEM1024, ss1, ct1); err != nil {
				panic(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	dkMLKEM768, _ := generateMLKEM768Key()
	ct2, ss2 := encapMLKEM768(dkMLKEM768.EncapsulationKey())
	b.Run("MLKEM-768", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := decapMLKEM768(dkMLKEM768, ss2, ct2); err != nil {
				panic(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})

	dkMLKEM1024, _ := generateMLKEM1024Key()
	ct3, ss3 := encapMLKEM1024(dkMLKEM1024.EncapsulationKey())
	b.Run("MLKEM-1024", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if err := decapMLKEM1024(dkMLKEM1024, ss3, ct3); err != nil {
				panic(err)
			}
		}
		b.ReportAllocs() // Reports allocs/op and B/op
	})
}
