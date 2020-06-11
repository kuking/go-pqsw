package cryptoutil

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/pkg/errors"
)

func SidhNewPair(keyType KeyType) (pvt *sidh.PrivateKey, pub *sidh.PublicKey, err error) {
	if keyType == KeyTypeSidhFp434 {
		pvt = sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		pub = sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
	} else if keyType == KeyTypeSidhFp503 {
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

func KeyId(pub []byte) string {
	return base64.StdEncoding.EncodeToString(QuickSha256(pub))
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

func SikePrivateKeyFromBytes(b []byte) *sidh.PrivateKey {
	var pvt *sidh.PrivateKey
	if len(b) == 44 {
		pvt = sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
	} else if len(b) == 56 {
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

func SikePublicKeyFromBytes(b []byte) *sidh.PublicKey {
	var pub *sidh.PublicKey
	if len(b) == 330 {
		pub = sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
	} else if len(b) == 378 {
		pub = sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)
	} else if len(b) == 564 {
		pub = sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	} else {
		return nil
	}
	if pub.Import(b) != nil {
		return nil
	}
	return pub
}
