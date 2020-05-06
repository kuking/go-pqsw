package cryptoutil

import "crypto/sha256"

type KeyType uint8

const (
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
