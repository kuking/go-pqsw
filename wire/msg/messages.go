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
	DisconnectCauseTooMuchSecurityRequested       uint32 = 3
	DisconnectCauseCounterpartyKeyIdNotRecognised uint32 = 4
	DisconnectCausePotpNotRecognised              uint32 = 5
	DisconnectCausePuzzleNotSolved                uint32 = 6
	DisconnectCauseSeverMisconfiguration          uint32 = 7

	SharedSecretRequestTypeKEMAndPotp uint8 = 0
)

var DisconnectCauseString = map[uint32]string{
	DisconnectCauseNone:                           "None",
	DisconnectCauseProtocolRequestedNotSupported:  "Protocol requested not supported",
	DisconnectCauseNotEnoughSecurityRequested:     "Not enough security Requested",
	DisconnectCauseCounterpartyKeyIdNotRecognised: "Counter party key not recognised",
	DisconnectCausePotpNotRecognised:              "Pragmatic one-time-pad (potp) not recognised",
	DisconnectCausePuzzleNotSolved:                "Puzzle not solved",
	DisconnectCauseSeverMisconfiguration:          "Server misconfiguration",
}

var SecureWireGoodState = []byte{'G', 'O', 'O', 'D'}

type WireType uint32

const WireTypeSimpleAES256 WireType = 1
const WireTypeTripleAES256 WireType = 2
const WireTypeTripleAES256Optional WireType = 3

type ClientHello struct {
	Protocol uint32
	WireType WireType
	KeyId    [256 / 8]byte
}

func (k *ClientHello) KeyIdAsString() string {
	return base64.StdEncoding.EncodeToString(k.KeyId[:])
}

const ClientHelloProtocol = 1

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
	WireType    WireType
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
