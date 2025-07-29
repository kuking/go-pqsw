package cryptoutil

import (
	"bytes"
	"testing"
)

func TestGenKeyInvalid(t *testing.T) {
	_, _, err := GenKey(KeyTypeInvalid)
	if err == nil {
		t.Error("It should have err when requesting an Invalid Key")
	}
}

func TestGenKeyFrodoVariants(t *testing.T) {
	for kt, name := range KeyTypeAsString {
		if name[0:5] == "FRODO" {
			pvt, pub, err := GenKey(kt)
			if err != nil {
				t.Error(err)
			}
			kem, err := FrodoGetKem(kt)
			if err != nil {
				t.Error(err)
			}

			if len(pvt) != kem.SecretKeyLen() {
				t.Error("Private Key size generated not right")
			}
			if len(pub) != kem.PublicKeyLen() {
				t.Error("Public Key size generated not right")
			}
		}
	}
}

func TestKeyId(t *testing.T) {
	for kt := range KeyTypeAsString {
		_, pub, err := GenKey(kt)
		if err != nil {
			t.Error(err)
		}
		if len(KeyId(pub)) != 44 {
			t.Fatal("this should look like an base64 of length 44")
		}
	}
}

func TestStringifyBytifyKeys(t *testing.T) {
	for kt := range KeyTypeAsString {
		pvt, pub, err := GenKey(kt)
		if err != nil {
			t.Fatal("creating keys should work")
		}
		pvtSt := PrivateKeyAsString(pvt)
		pubSt := PublicKeyAsString(pub)

		pvtRoundTrip := PrivateKeyFromString(pvtSt)
		pubRoundTrip := PublicKeyFromString(pubSt)
		if !bytes.Equal(pvt, pvtRoundTrip) || !bytes.Equal(pub, pubRoundTrip) {
			t.Fatal("round trip key after converting to string does not seems to be the same")
		}
	}
}

func TestStringifyBorderCases(t *testing.T) {
	if PrivateKeyFromString("") != nil ||
		PublicKeyFromString("") != nil ||
		PrivateKeyFromString("!") != nil ||
		PublicKeyFromString("!") != nil ||
		PrivateKeyFromString("aGkK") != nil ||
		PublicKeyFromString("aGkK") != nil {
		t.Fatal("invalid string representation of key should fail")
	}
}
