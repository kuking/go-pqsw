package cryptoutil

import (
	"crypto/rand"
	"github.com/Yawning/kyber"
	"github.com/pkg/errors"
)

func kyberGenKey(keyType KeyType) (pvt []byte, pub []byte, err error) {
	var parameterSet *kyber.ParameterSet
	if keyType == KeyTypeKyber512 {
		parameterSet = kyber.Kyber512
	} else if keyType == KeyTypeKyber768 {
		parameterSet = kyber.Kyber768
	} else if keyType == KeyTypeKyber1024 {
		parameterSet = kyber.Kyber1024
	} else {
		err = errors.Errorf("I do not know how to create a key type %d.", keyType)
		return

	}
	kPub, kPvt, err := parameterSet.GenerateKeyPair(rand.Reader)
	if err != nil {
		return
	}
	pub = kPub.Bytes()
	pvt = kPvt.Bytes()
	return
}

func kyberParameters(keyType KeyType) (params *kyber.ParameterSet, err error) {
	switch keyType {
	case KeyTypeKyber512:
		params = kyber.Kyber512
	case KeyTypeKyber768:
		params = kyber.Kyber768
	case KeyTypeKyber1024:
		params = kyber.Kyber1024
	default:
		err = errors.Errorf("I don't know how to create a Kyber keyType %v", keyType)
	}
	return
}

func kyberEncapsulate(pub []byte, keyType KeyType) (ct []byte, ss []byte, err error) {
	kyberParams, err := kyberParameters(keyType)
	if err != nil {
		return
	}
	kPub, err := kyberParams.PublicKeyFromBytes(pub)
	if err != nil {
		return
	}
	ct, ss, err = kPub.KEMEncrypt(rand.Reader)
	return
}

func kyberDencapsulate(pvt []byte, ct []byte, keyType KeyType) (ss []byte, err error) {
	kyberParms, err := kyberParameters(keyType)
	if err != nil {
		return
	}
	kPvt, err := kyberParms.PrivateKeyFromBytes(pvt)
	if err != nil {
		return
	}
	ss = kPvt.KEMDecrypt(ct)
	return
}
