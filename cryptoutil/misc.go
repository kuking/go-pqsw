package cryptoutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"golang.org/x/crypto/scrypt"
)

type KeyType uint8

const (
	KeyTypeUnknown        KeyType = 255
	KeyTypeInvalid        KeyType = iota
	KeyTypeSidhFp434      KeyType = iota
	KeyTypeSidhFp503      KeyType = iota
	KeyTypeSidhFp751      KeyType = iota
	KeyTypeFrodo640AES    KeyType = iota
	KeyTypeFrodo640SHAKE  KeyType = iota
	KeyTypeFrodo976AES    KeyType = iota
	KeyTypeFrodo976SHAKE  KeyType = iota
	KeyTypeFrodo1344AES   KeyType = iota
	KeyTypeFrodo1344SHAKE KeyType = iota
	KeyTypeKyber512       KeyType = iota
	KeyTypeKyber768       KeyType = iota
	KeyTypeKyber1024      KeyType = iota
)

var KeyTypeAsString = map[KeyType]string{
	KeyTypeSidhFp434:      "SIKE_FP434",
	KeyTypeSidhFp503:      "SIKE_FP503",
	KeyTypeSidhFp751:      "SIKE_FP751",
	KeyTypeFrodo640AES:    "FRODO_640_AES",
	KeyTypeFrodo640SHAKE:  "FRODO_640_SHAKE",
	KeyTypeFrodo976AES:    "FRODO_976_AES",
	KeyTypeFrodo976SHAKE:  "FRODO_976_SHAKE",
	KeyTypeFrodo1344AES:   "FRODO_1344_AES",
	KeyTypeFrodo1344SHAKE: "FRODO_1344_SHAKE",
	KeyTypeKyber512:       "KYBER_512",
	KeyTypeKyber768:       "KYBER_768",
	KeyTypeKyber1024:      "KYBER_1024",
}

type KemSizes struct {
	Private      int
	Public       int
	CipherText   int
	SharedSecret int
}

var CipherTextSizeByKeyType = map[KeyType]KemSizes{
	KeyTypeSidhFp434:      {374, 330, 346, 16},
	KeyTypeSidhFp503:      {434, 378, 402, 24},
	KeyTypeSidhFp751:      {644, 564, 596, 32},
	KeyTypeFrodo640AES:    {19888, 9616, 9720, 16},
	KeyTypeFrodo640SHAKE:  {19888, 9616, 9720, 16},
	KeyTypeFrodo976AES:    {31296, 15632, 15744, 24},
	KeyTypeFrodo976SHAKE:  {31296, 15632, 15744, 24},
	KeyTypeFrodo1344AES:   {43088, 21520, 21632, 32},
	KeyTypeFrodo1344SHAKE: {43088, 21520, 21632, 32},
	KeyTypeKyber512:       {1632, 736, 800, 16},
	KeyTypeKyber768:       {2400, 1088, 1152, 24},
	KeyTypeKyber1024:      {3168, 1568, 1504, 32},
}

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

func QuickSha256(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func RandBytes(size int) []byte {
	res := make([]byte, size)
	n, err := rand.Read(res)
	if n != size || err != nil {
		panic("could not generate randomness")
	}
	return res
}

func EncB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func ConcatAll(parts ...[]byte) (res []byte) {
	res = make([]byte, 0)
	for _, part := range parts {
		res = append(res, part...)
	}
	return res
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
