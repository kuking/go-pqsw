package msg

type KnockKnock struct {
	KeyId           [256 / 8]byte
	ProtocolVersion uint32
	WireType        uint32
}

const ProtocolVersion = 1
const WireType_SimpleAES256 = 1
const WireType_TripleAES256 = 2

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
	KeyId [256 / 8]byte
	Bits  uint16
}
