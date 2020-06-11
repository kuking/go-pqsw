package cryptoutil

import (
	"crypto/rand"
	"github.com/cloudflare/circl/dh/sidh"
	frodo "github.com/kuking/go-frodokem"
	"github.com/pkg/errors"
)

func FrodoKEMFromKeyType(keyType KeyType) (kem frodo.FrodoKEM, err error) {
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

func GenKey(keyType KeyType) (pvt []byte, pub []byte, err error) {

	var sikePvt *sidh.PrivateKey
	var sikePub *sidh.PublicKey

	if keyType == KeyTypeSidhFp503 {
		sikePvt = sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSike)
		sikePub = sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)
	} else if keyType == KeyTypeSidhFp751 {
		sikePvt = sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
		sikePub = sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	} else {
		var kem frodo.FrodoKEM
		kem, err = FrodoKEMFromKeyType(keyType)
		if err != nil {
			err = errors.Errorf("I do not know how to create a key type %d.", keyType)
			return
		}
		pub, pvt = kem.Keygen()
		return
	}

	// common Sike keygen
	if sikePvt != nil && sikePub != nil {
		err = sikePvt.Generate(rand.Reader)
		if err != nil {
			return
		}
		sikePvt.GeneratePublicKey(sikePub)
		pub = SidhBytesFromPublicKey(sikePub)
		pvt = SidhBytesFromPrivateKey(sikePvt)
	} else {
		err = errors.New("This code is inconsistent, maybe needs more work.")
	}

	return
}
