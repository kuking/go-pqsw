package cryptoutil

import (
	"crypto/rand"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/pkg/errors"
)

func SikeBytesFromPrivateKey(pvt *sidh.PrivateKey) []byte {
	b := make([]byte, pvt.Size())
	pvt.Export(b)
	return b
}

func SikeBytesFromPublicKey(pvt *sidh.PublicKey) []byte {
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

func SikeGetKem(keyType KeyType) (*sidh.KEM, error) {
	switch keyType {
	case KeyTypeSidhFp434:
		return sidh.NewSike434(rand.Reader), nil
	case KeyTypeSidhFp503:
		return sidh.NewSike503(rand.Reader), nil
	case KeyTypeSidhFp751:
		return sidh.NewSike751(rand.Reader), nil
	default:
		return nil, errors.New("can not create kem for key")
	}
}
