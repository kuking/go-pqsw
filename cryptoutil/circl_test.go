package cryptoutil

import (
	"crypto/rand"
	"github.com/cloudflare/circl/dh/sidh"
	"testing"
)

func BenchmarkSidhNewPair_Fp434(b *testing.B) {
	_, _, err := GenKey(KeyTypeSidhFp434)
	if err != nil {
		b.Error(b)
	}
}

func BenchmarkSidhNewPair_Fp503(b *testing.B) {
	_, _, err := GenKey(KeyTypeSidhFp503)
	if err != nil {
		b.Error(b)
	}

}

func BenchmarkSidhNewPair_Fp751(b *testing.B) {
	_, _, err := GenKey(KeyTypeSidhFp751)
	if err != nil {
		b.Error(b)
	}
}

func commonBenchKEM(kem *sidh.KEM, pvt *sidh.PrivateKey, pub *sidh.PublicKey, b *testing.B) {
	cipherText := make([]byte, kem.CiphertextSize())
	secret := make([]byte, kem.SharedSecretSize())
	for i := 0; i < b.N; i++ {
		kem.Encapsulate(cipherText, secret, pub)
		kem.Decapsulate(secret, pvt, pub, cipherText)
	}
}

func BenchmarkKEM_Fp434(b *testing.B) {
	pvt, pub, _ := GenKey(KeyTypeSidhFp434)
	kem := sidh.NewSike434(rand.Reader)
	commonBenchKEM(kem, SikePrivateKeyFromBytes(pvt), SikePublicKeyFromBytes(pub), b)
}

func BenchmarkKEM_Fp503(b *testing.B) {
	pvt, pub, _ := GenKey(KeyTypeSidhFp503)
	kem := sidh.NewSike503(rand.Reader)
	commonBenchKEM(kem, SikePrivateKeyFromBytes(pvt), SikePublicKeyFromBytes(pub), b)
}

func BenchmarkKEM_Fp751(b *testing.B) {
	pvt, pub, _ := GenKey(KeyTypeSidhFp751)
	kem := sidh.NewSike751(rand.Reader)
	commonBenchKEM(kem, SikePrivateKeyFromBytes(pvt), SikePublicKeyFromBytes(pub), b)
}
