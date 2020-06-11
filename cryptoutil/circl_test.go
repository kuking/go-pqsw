package cryptoutil

import (
	"crypto/rand"
	"github.com/cloudflare/circl/dh/sidh"
	"testing"
)

func TestSidhNewPair(t *testing.T) {
	pvt, pub, err := SidhNewPair(KeyTypeInvalid)
	if pvt != nil || pub != nil || err == nil {
		t.Fatal("invalid KeyType should err")
	}

	pvt, pub, err = SidhNewPair(KeyTypeSidhFp434)
	if pvt == nil || pub == nil || err != nil {
		t.Fatal("could not create key")
	}
	if pvt.Size() != 44 {
		t.Fatal("Fp434 private sidh key should have size 44")
	}
	if pub.Size() != 330 {
		t.Fatal("Fp434 public sidh key should have size 330")
	}

	pvt, pub, err = SidhNewPair(KeyTypeSidhFp503)
	if pvt == nil || pub == nil || err != nil {
		t.Fatal("could not create key")
	}
	if pvt.Size() != 56 {
		t.Fatal("Fp503 private sidh key should have size 56")
	}
	if pub.Size() != 378 {
		t.Fatal("Fp503 public sidh key should have size 378")
	}

	pvt, pub, err = SidhNewPair(KeyTypeSidhFp751)
	if pvt == nil || pub == nil || err != nil {
		t.Fatal("could not create key")
	}
	if pvt.Size() != 80 {
		t.Fatal("Fp751 private sidh key should have size 80")
	}
	if pub.Size() != 564 {
		t.Fatal("Fp751 public sidh key should have size 564")
	}

}

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
	pvt, pub, _ := SidhNewPair(KeyTypeSidhFp434)
	kem := sidh.NewSike503(rand.Reader)
	commonBenchKEM(kem, pvt, pub, b)
}

func BenchmarkKEM_Fp503(b *testing.B) {
	pvt, pub, _ := SidhNewPair(KeyTypeSidhFp503)
	kem := sidh.NewSike503(rand.Reader)
	commonBenchKEM(kem, pvt, pub, b)
}

func BenchmarkKEM_Fp751(b *testing.B) {
	pvt, pub, _ := SidhNewPair(KeyTypeSidhFp751)
	kem := sidh.NewSike751(rand.Reader)
	commonBenchKEM(kem, pvt, pub, b)
}
