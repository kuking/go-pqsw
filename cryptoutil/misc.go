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
