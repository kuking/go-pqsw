package cryptoutil

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type KeyType uint8

const (
	KeyTypeUnknown   KeyType = 255
	KeyTypeInvalid   KeyType = 0
	KeyTypeSidhFp503 KeyType = 1
	KeyTypeSidhFp751 KeyType = 2
)

var KeyTypeAsString = map[KeyType]string{
	KeyTypeSidhFp503: "SIDH_FP503",
	KeyTypeSidhFp751: "SIDH_FP751",
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