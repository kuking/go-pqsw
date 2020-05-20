package cryptoutil

import (
	"bytes"
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

func TestStringifyBytifyKeys(t *testing.T) {
	for _, kt := range []KeyType{KeyTypeSidhFp434, KeyTypeSidhFp503, KeyTypeSidhFp751} {
		pvt, pub, err := SidhNewPair(kt)
		if err != nil {
			t.Fatal("creating keys should work")
		}
		pvtSt := SidhPrivateKeyAsString(pvt)
		pubSt := SidhPublicKeyAsString(pub)
		pvtRoundTrip := SidhPrivateKeyFromString(pvtSt)
		pubRoundTrip := SidhPublicKeyFromString(pubSt)
		if !bytes.Equal(pvt.S, pvtRoundTrip.S) ||
			!bytes.Equal(pvt.Scalar, pvtRoundTrip.Scalar) ||
			!bytes.Equal(SidhBytesFromPrivateKey(pvt), SidhBytesFromPrivateKey(pvtRoundTrip)) ||
			!bytes.Equal(SidhBytesFromPublicKey(pub), SidhBytesFromPublicKey(pubRoundTrip)) {
			t.Fatal("round trip key after converting to string does not seems to be the same")
		}
	}
}

func TestStringifyBorderCases(t *testing.T) {
	if SidhPrivateKeyFromString("") != nil ||
		SidhPublicKeyFromString("") != nil ||
		SidhPrivateKeyFromString("!") != nil ||
		SidhPublicKeyFromString("!") != nil ||
		SidhPrivateKeyFromString("aGkK") != nil ||
		SidhPublicKeyFromString("aGkK") != nil {
		t.Fatal("invalid string representation of key should fail")
	}
}

func TestKeyId(t *testing.T) {
	_, pub, _ := SidhNewPair(KeyTypeSidhFp434)
	if len(SidhKeyId(pub)) != 44 {
		t.Fatal("this should look like an base64 of length 44")
	}
	_, pub, _ = SidhNewPair(KeyTypeSidhFp503)
	if len(SidhKeyId(pub)) != 44 {
		t.Fatal("this should look like an base64 of length 44")
	}
	_, pub, _ = SidhNewPair(KeyTypeSidhFp751)
	if len(SidhKeyId(pub)) != 44 {
		t.Fatal("this should look like an base64 of length 44")
	}
}

func BenchmarkSidhNewPair_Fp434(b *testing.B) {
	SidhNewPair(KeyTypeSidhFp434)
}

func BenchmarkSidhNewPair_Fp503(b *testing.B) {
	SidhNewPair(KeyTypeSidhFp503)
}

func BenchmarkSidhNewPair_Fp751(b *testing.B) {
	SidhNewPair(KeyTypeSidhFp751)
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
