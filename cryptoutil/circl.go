package cryptoutil

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/pkg/errors"
)

func SidhNewPair(keyType KeyType) (pvt *sidh.PrivateKey, pub *sidh.PublicKey, err error) {
	if keyType == KeyTypeSidhFp503 {
		pvt = sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSike)
		pub = sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)
	} else if keyType == KeyTypeSidhFp751 {
		pvt = sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
		pub = sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	} else {
		return nil, nil, errors.Errorf("I do not know how to create a key type %d.", keyType)
	}
	err = pvt.Generate(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pvt.GeneratePublicKey(pub)
	return pvt, pub, err
}

func SidhPrivateKeyFromString(key string) *sidh.PrivateKey {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil
	}
	return SidhPrivateKeyFromBytes(b)
}

func SidhPublicKeyFromString(key string) *sidh.PublicKey {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil
	}
	return SidhPublicKeyFromBytes(b)
}

func SidhPublicKeyAsString(pub *sidh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(SidhBytesFromPublicKey(pub))
}

func SidhPrivateKeyAsString(pub *sidh.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(SidhBytesFromPrivateKey(pub))
}

func SidhKeyId(pub *sidh.PublicKey) string {
	return base64.StdEncoding.EncodeToString(QuickSha256(SidhBytesFromPublicKey(pub)))
}

func SidhBytesFromPrivateKey(pvt *sidh.PrivateKey) []byte {
	b := make([]byte, pvt.Size())
	pvt.Export(b)
	return b
}

func SidhBytesFromPublicKey(pvt *sidh.PublicKey) []byte {
	b := make([]byte, pvt.Size())
	pvt.Export(b)
	return b
}

func SidhPrivateKeyFromBytes(b []byte) *sidh.PrivateKey {
	var pvt *sidh.PrivateKey
	if len(b) == 56 {
		pvt = sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSike)
	} else if len(b) == 80 {
		pvt = sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
	} else {
		return nil
	}
	if pvt.Import(b) != nil {
		return nil
	}
	return pvt
}

func SidhPublicKeyFromBytes(b []byte) *sidh.PublicKey {
	var pvt *sidh.PublicKey
	if len(b) == 378 {
		pvt = sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)
	} else if len(b) == 564 {
		pvt = sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	} else {
		return nil
	}
	if pvt.Import(b) != nil {
		return nil
	}
	return pvt
}
