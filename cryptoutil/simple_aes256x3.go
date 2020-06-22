package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/pkg/errors"
	"golang.org/x/crypto/scrypt"
)

type SCryptParameters struct {
	N int
	R int
	P int
}

var CurrentSCryptParameters = SCryptParameters{
	N: 65536 * 2,
	R: 8,
	P: 1,
}

type SimpleTripleEncryptionHeader struct {
	Magic        uint32
	Salt         [32 * 3]byte
	Nonces       [12 * 3]byte
	SCryptParams SCryptParameters
}

func AES256CGMSeal(key, nonce, plainText []byte) (cipherText []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	cipherText = aead.Seal(nil, nonce, plainText, nil)
	return
}

func AES256CGMOpen(key, nonce, cipherText []byte) (plainText []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return
	}
	return aead.Open(nil, nonce, cipherText, nil)
}

// Creates a []byte encrypted with Triple AES256-CGM using Scrypt to derive the password.
func SimpleSuperTripleEncrypt(plainText []byte, password string) (cipherText []byte, err error) {
	keyLen := 32 * 3
	salt := RandBytes(keyLen)
	nonces := RandBytes(12 * 3)
	key, err := scrypt.Key([]byte(password), salt, CurrentSCryptParameters.N, CurrentSCryptParameters.R, CurrentSCryptParameters.P, keyLen)
	if err != nil {
		return
	}
	cipher1, err := AES256CGMSeal(key[0:32], nonces[0:12], plainText)
	if err != nil {
		return
	}
	cipher2, err := AES256CGMSeal(key[32:64], nonces[12:24], cipher1)
	if err != nil {
		return
	}
	cipher3, err := AES256CGMSeal(key[64:96], nonces[24:36], cipher2)
	if err != nil {
		return
	}
	cipherText = make([]byte, len(cipher3)+len(salt)+len(nonces)+2)
	cipherText[0] = 0xbe
	cipherText[1] = 0xef
	copy(cipherText[2:], salt)
	copy(cipherText[2+len(salt):], nonces)
	copy(cipherText[2+len(salt)+len(nonces):], cipher3)
	return
}

func SimpleSuperTripleDecrypt(cipherText []byte, password string) (plainText []byte, err error) {
	if cipherText[0] != 0xbe || cipherText[1] != 0xef {
		err = errors.New("magic bytes are not valid ... might not be encrypted with this method")
		return
	}
	keyLen := 32 * 3
	salt := make([]byte, keyLen)
	copy(salt, cipherText[2:])
	nonces := make([]byte, 12*3)
	copy(nonces, cipherText[2+len(salt):])
	key, err := scrypt.Key([]byte(password), salt, CurrentSCryptParameters.N, CurrentSCryptParameters.R, CurrentSCryptParameters.P, keyLen)
	cipher2, err := AES256CGMOpen(key[64:96], nonces[24:36], cipherText[2+len(salt)+len(nonces):])
	if err != nil {
		return
	}
	cipher1, err := AES256CGMOpen(key[32:64], nonces[12:24], cipher2)
	if err != nil {
		return
	}
	return AES256CGMOpen(key[0:32], nonces[0:12], cipher1)
}
