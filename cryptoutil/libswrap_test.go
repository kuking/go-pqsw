package cryptoutil

import (
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

	pvt, pub, err := GenKey(KeyTypeSidhFp503)
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
