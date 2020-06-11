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

func TestGenKeyFrodoAllVariants(t *testing.T) {
	for keyType, name := range KeyTypeAsString {
		if name[0:5] == "FRODO" {
			kem, err := FrodoKEMFromKeyType(keyType)
			if err != nil {
				t.Error(err)
			}
			pvt, pub, err := GenKey(keyType)
			if err != nil {
				t.Error(err)
			}
			if len(pub) != kem.PublicKeyLen() {
				t.Error("It did not return the right public key length")
			}
			if len(pvt) != kem.SecretKeyLen() {
				t.Error("It did not return the right private key length")
			}
		}
	}
}

func TestGenKeySikeVariants(t *testing.T) {
	pvt, pub, err := GenKey(KeyTypeSidhFp434)
	if err != nil {
		t.Error(err)
	}
	if len(pvt) != 44 {
		t.Error("It did not return the right private key length")
	}
	if len(pub) != 330 {
		t.Error("It did not return the right public key length")
	}

	pvt, pub, err = GenKey(KeyTypeSidhFp503)
	if err != nil {
		t.Error(err)
	}
	if len(pvt) != 56 {
		t.Error("It did not return the right private key length")
	}
	if len(pub) != 378 {
		t.Error("It did not return the right public key length")
	}

	pvt, pub, err = GenKey(KeyTypeSidhFp751)
	if err != nil {
		t.Error(err)
	}
	if len(pvt) != 80 {
		t.Error("It did not return the right private key length")
	}
	if len(pub) != 564 {
		t.Error("It did not return the right public key length")
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
