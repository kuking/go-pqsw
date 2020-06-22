package cryptoutil

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"github.com/pkg/errors"
	"golang.org/x/crypto/scrypt"
)

type SCryptParameters struct {
	N uint32
	R uint32
	P uint32
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

const SimpleTripleEncryptionHeaderLen int = 4*4 + 96 + 36

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

	var header = SimpleTripleEncryptionHeader{
		Magic:        0xbeef,
		Salt:         [96]byte{},
		Nonces:       [36]byte{},
		SCryptParams: CurrentSCryptParameters,
	}
	copy(header.Salt[:], RandBytes(96))
	copy(header.Nonces[:], RandBytes(36))

	key, err := scrypt.Key([]byte(password), header.Salt[:],
		int(header.SCryptParams.N), int(header.SCryptParams.R), int(header.SCryptParams.P), 32*3)
	if err != nil {
		return
	}
	cipher1, err := AES256CGMSeal(key[0:32], header.Nonces[0:12], plainText)
	if err != nil {
		return
	}
	cipher2, err := AES256CGMSeal(key[32:64], header.Nonces[12:24], cipher1)
	if err != nil {
		return
	}
	cipher3, err := AES256CGMSeal(key[64:96], header.Nonces[24:36], cipher2)
	if err != nil {
		return
	}

	var buf bytes.Buffer
	err = binary.Write(&buf, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	_, err = buf.Write(cipher3)
	if err != nil {
		return
	}
	cipherText = buf.Bytes()
	return
}

func SimpleSuperTripleDecrypt(cipherText []byte, password string) (plainText []byte, err error) {
	buf := bytes.NewReader(cipherText)
	var header = SimpleTripleEncryptionHeader{}
	err = binary.Read(buf, binary.LittleEndian, &header)
	if err != nil {
		return
	}
	if header.Magic != 0xbeef {
		err = errors.New("magic bytes are not valid ... might not be encrypted with this method")
		return
	}

	if header.SCryptParams.N > CurrentSCryptParameters.N<<2 ||
		header.SCryptParams.P > CurrentSCryptParameters.P<<2 ||
		header.SCryptParams.R > CurrentSCryptParameters.R<<2 {
		err = errors.New("header scrypt parameters too far away, likely to be a DoS and not an organic increment")
		return
	}

	key, err := scrypt.Key([]byte(password), header.Salt[:],
		int(header.SCryptParams.N), int(header.SCryptParams.R), int(header.SCryptParams.P), 96)
	if err != nil {
		return
	}
	cipher3 := cipherText[SimpleTripleEncryptionHeaderLen:]
	cipher2, err := AES256CGMOpen(key[64:96], header.Nonces[24:36], cipher3)
	if err != nil {
		return
	}
	cipher1, err := AES256CGMOpen(key[32:64], header.Nonces[12:24], cipher2)
	if err != nil {
		return
	}
	return AES256CGMOpen(key[0:32], header.Nonces[0:12], cipher1)
}
