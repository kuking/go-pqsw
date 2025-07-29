package cryptoutil

import (
	"crypto/mlkem"
	"github.com/pkg/errors"
)

func kyberGenKey(keyType KeyType) (pvt []byte, pub []byte, err error) {
	if keyType == KeyTypeKyber768 {
		var dk *mlkem.DecapsulationKey768
		dk, err = mlkem.GenerateKey768()
		if err != nil {
			return
		}
		pvt = dk.Bytes()
		pub = dk.EncapsulationKey().Bytes()
	} else if keyType == KeyTypeKyber1024 {
		var dk *mlkem.DecapsulationKey1024
		dk, err = mlkem.GenerateKey1024()
		if err != nil {
			return
		}
		pvt = dk.Bytes()
		pub = dk.EncapsulationKey().Bytes()
	} else {
		err = errors.Errorf("I do not know how to create a key type %d.", keyType)
	}
	return
}

func kyberEncapsulate(pub []byte, keyType KeyType) (ct []byte, ss []byte, err error) {

	if keyType == KeyTypeKyber768 {
		ek, err := mlkem.NewEncapsulationKey768(pub)
		if err != nil {
			return nil, nil, err
		}
		ss, ct = ek.Encapsulate()
	} else if keyType == KeyTypeKyber1024 {
		ek, err := mlkem.NewEncapsulationKey1024(pub)
		if err != nil {
			return nil, nil, err
		}
		ss, ct = ek.Encapsulate()
	} else {
		return nil, nil, errors.New("I do not know how to encapsulate this key type")
	}
	return
}

func kyberDencapsulate(pvt []byte, ct []byte, keyType KeyType) (ss []byte, err error) {
	if keyType == KeyTypeKyber768 {
		dk, err := mlkem.NewDecapsulationKey768(pvt)
		if err != nil {
			return nil, err
		}
		return dk.Decapsulate(ct)
	} else if keyType == KeyTypeKyber1024 {
		dk, err := mlkem.NewDecapsulationKey1024(pvt)
		if err != nil {
			return nil, err
		}
		return dk.Decapsulate(ct)
	}
	return nil, errors.New("I do not know how to encapsulate this key type")
}
