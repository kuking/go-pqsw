package cryptoutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
