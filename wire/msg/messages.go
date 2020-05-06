package msg

import "encoding/base64"

type Knock struct {
	KeyId           [256 / 8]byte
	ProtocolVersion uint32
	WireType        uint32
}

func (k *Knock) KeyIdAsString() string {
	return base64.StdEncoding.EncodeToString(k.KeyId[:])
}

const ProtocolVersion = 1
const WireTypeSimpleAES256 = 1
const WireTypeTripleAES256 = 2

type PuzzleRequest struct {
	Puzzle uint16
	Body   [64]byte
	Param  uint16
}

type PuzzleResponse struct {
	Response [64]byte
}

const PuzzleSHA512LZ = 1
const SHA512LZParam = 16

type SharedSecretRequest struct {
	KeyId  [256 / 8]byte
	Counts uint16
}

// Message used in the wire, describes how many 'SecretsCount' of size 'SecretSize' to read.
type SharedSecretBundleDescriptionResponse struct {
	SecretsCount uint8
	SecretSize   uint16
}

type SharedSecret struct {
	Shared [][]byte
}
