package wire

type KnockKnock struct {
	KeyId           [256 / 8]byte
	ProtocolVersion uint32
	WireType        uint32
}

type HashRequest struct {
	KeyDerivationAlgo uint16
	Payload           [64]byte
	Iterations        uint32
}

const HashRequestScrypt = 1
