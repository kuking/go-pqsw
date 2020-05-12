package msg

import "encoding/base64"

type DisconnectCause struct {
	Delimiter uint32
	Cause     uint32
}

const (
	DisconnectCauseDelimiter                      uint32 = 0xdeadbeef
	DisconnectCauseNone                           uint32 = 0
	DisconnectCauseProtocolRequestedNotSupported  uint32 = 1
	DisconnectCauseNotEnoughSecurityRequested     uint32 = 2
	DisconnectCauseCounterpartyKeyIdNotRecognised uint32 = 3
	DisconnectCausePotpNotRecognised              uint32 = 4
	DisconnectCausePuzzleNotSolved                uint32 = 5
	DisconnectCauseSeverMisconfiguration          uint32 = 6

	SharedSecretRequestTypeKEMAndPotp uint8 = 0
)

var SecureWireGoodState = []byte{'G', 'O', 'O', 'D'}

type ClientHello struct {
	Protocol uint32
	WireType uint32
	KeyId    [256 / 8]byte
}

func (k *ClientHello) KeyIdAsString() string {
	return base64.StdEncoding.EncodeToString(k.KeyId[:])
}

const ClientHelloProtocol = 1
const ClientHelloWireTypeSimpleAES256 = 1
const ClientHelloWireTypeTripleAES256 = 2

type PuzzleRequest struct {
	Puzzle uint16
	Body   [64]byte
	Param  uint16
}

const PuzzleSHA512LZ = 1

type PuzzleResponse struct {
	Response [64]byte
}

type SharedSecretRequest struct {
	RequestType uint8 // fix=0, fix proposal of keys and Potps, open to make an unbounded list in the future
	KeyId       [256 / 8]byte
}

func (s *SharedSecretRequest) KeyIdPreferredAsString() string {
	return base64.StdEncoding.EncodeToString(s.KeyId[:])
}

// Message used in the wire, describes how many 'SecretsCount' of size 'SecretSize' to read.
type SharedSecretBundleDescriptionResponse struct {
	PotpIdUsed   [256 / 8]byte
	PotpOffset   uint64
	SecretsCount uint8
	SecretSize   uint16
}

func (b *SharedSecretBundleDescriptionResponse) PotpIdAsString() string {
	return base64.StdEncoding.EncodeToString(b.PotpIdUsed[:])
}

type SharedSecret struct {
	Otp    []byte
	Shared [][]byte
}

func (s *SharedSecret) SharesJoined() []byte {
	res := make([]byte, len(s.Shared)*len(s.Shared[0]))
	for i := 0; i < len(s.Shared); i++ {
		res = append(res, s.Shared[i]...)
	}
	return res
}
