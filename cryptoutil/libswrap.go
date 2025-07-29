package cryptoutil

import (
	"encoding/base64"
	"github.com/pkg/errors"
)

func KeyId(pub []byte) string {
	return base64.StdEncoding.EncodeToString(QuickSha256(pub))
}

func GenKey(keyType KeyType) (pvt []byte, pub []byte, err error) {
	keyName := KeyTypeAsString[keyType]
	if keyName == "" {
		keyName = "UNKNOWN"
	}

	if keyName[:5] == "FRODO" {
		return frodoGenKey(keyType)
	} else if keyName[:5] == "KYBER" {
		return kyberGenKey(keyType)
	} else {
		err = errors.Errorf("I do not know how to create a key type %d.", keyType)
		return
	}
}

func Encapsulate(pub []byte, keyType KeyType) (ct []byte, ss []byte, err error) {
	keyName := KeyTypeAsString[keyType]
	if keyName[:5] == "FRODO" {
		return frodoEncapsulate(pub, keyType)
	} else if keyName[:5] == "KYBER" {
		return kyberEncapsulate(pub, keyType)
	} else {
		err = errors.Errorf("Encapsulate does not know how to handle key type: %v", keyName)
		return
	}
}

func Dencapsulate(pub []byte, pvt []byte, ct []byte, keyType KeyType) (ss []byte, err error) {
	keyName := KeyTypeAsString[keyType]
	if keyName[:5] == "FRODO" {
		return frodoDencapsulate(pvt, ct, keyType)
	} else if keyName[:5] == "KYBER" {
		return kyberDencapsulate(pvt, ct, keyType)
	} else {
		err = errors.Errorf("Encapsulate does not know how to handle key type: %v", keyName)
		return
	}
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
