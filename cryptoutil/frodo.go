package cryptoutil

import (
	frodo "github.com/kuking/go-frodokem"
	"github.com/pkg/errors"
)

func frodoGenKey(keyType KeyType) (pvt []byte, pub []byte, err error) {
	var kem frodo.FrodoKEM
	kem, err = FrodoGetKem(keyType)
	if err != nil {
		err = errors.Errorf("I do not know how to create a key type %d.", keyType)
	}
	pub, pvt = kem.Keygen()
	return
}

func FrodoGetKem(keyType KeyType) (kem frodo.FrodoKEM, err error) {
	if keyType == KeyTypeFrodo640AES {
		kem = frodo.Frodo640AES()
	} else if keyType == KeyTypeFrodo640SHAKE {
		kem = frodo.Frodo640SHAKE()
	} else if keyType == KeyTypeFrodo976AES {
		kem = frodo.Frodo976AES()
	} else if keyType == KeyTypeFrodo976SHAKE {
		kem = frodo.Frodo976SHAKE()
	} else if keyType == KeyTypeFrodo1344AES {
		kem = frodo.Frodo1344AES()
	} else if keyType == KeyTypeFrodo1344SHAKE {
		kem = frodo.Frodo1344SHAKE()
	} else {
		err = errors.Errorf("I don't know how to build a FrodoKEM using %v keyType", keyType)
	}
	return
}

func frodoEncapsulate(pub []byte, keyType KeyType) (ct []byte, ss []byte, err error) {
	kem, err := FrodoGetKem(keyType)
	if err != nil {
		return
	}
	ct, ss, err = kem.Encapsulate(pub)
	return
}

func frodoDencapsulate(pvt []byte, ct []byte, keyType KeyType) (ss []byte, err error) {
	kem, err := FrodoGetKem(keyType)
	if err != nil {
		return
	}
	return kem.Dencapsulate(pvt, ct)
}
