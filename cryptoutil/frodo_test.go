package cryptoutil

import (
	"testing"
)

func TestGenKeyFrodoAllVariants(t *testing.T) {
	for keyType, name := range KeyTypeAsString {
		if name[0:5] == "FRODO" {
			kem, err := FrodoGetKem(keyType)
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
