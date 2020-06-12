package cryptoutil

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/cloudflare/circl/dh/sidh"
	frodo "github.com/kuking/go-frodokem"
	"github.com/pkg/errors"
)

func KeyId(pub []byte) string {
	return base64.StdEncoding.EncodeToString(QuickSha256(pub))
}

func GenKey(keyType KeyType) (pvt []byte, pub []byte, err error) {

	var sikePvt *sidh.PrivateKey
	var sikePub *sidh.PublicKey

	if keyType == KeyTypeSidhFp434 {
		sikePvt = sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		sikePub = sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
	} else if keyType == KeyTypeSidhFp503 {
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
		pub = SikeBytesFromPublicKey(sikePub)
		pvt = SikeBytesFromPrivateKey(sikePvt)
	} else {
		err = errors.New("This code is inconsistent, maybe needs more work.")
	}

	return
}

func Encapsulate(pub []byte, keyType KeyType) (ct []byte, ss []byte, err error) {
	sikePub := SikePublicKeyFromBytes(pub)
	kem, err := SikeGetKem(keyType)
	if err != nil {
		return nil, nil, err
	}
	ct = make([]byte, kem.CiphertextSize())
	ss = make([]byte, kem.SharedSecretSize())
	err = kem.Encapsulate(ct, ss, sikePub)
	if err != nil {
		return nil, nil, err
	}
	return
}

func Dencapsulate(pub []byte, pvt []byte, ct []byte, keyType KeyType) (ss []byte, err error) {
	sikePub := SikePublicKeyFromBytes(pub)
	sikePvt := SikePrivateKeyFromBytes(pvt)
	kem, err := SikeGetKem(keyType)
	if err != nil {
		return nil, err
	}
	ss = make([]byte, kem.SharedSecretSize())
	err = kem.Decapsulate(ss, sikePvt, sikePub, ct)
	if err != nil {
		return nil, err

	}
	return
}

func PublicKeyAsString(pub []byte) string {
	return base64.StdEncoding.EncodeToString(pub)
}

func PrivateKeyAsString(pub []byte) string {
	return base64.StdEncoding.EncodeToString(pub)
}

func PrivateKeyFromString(key string) (pvt []byte) {
	pvt, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(pvt) < 10 {
		return nil
	}
	return
}

func PublicKeyFromString(key string) (pub []byte) {
	pub, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(pub) < 10 {
		return nil
	}
	return
}
