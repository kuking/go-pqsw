package msg

import "encoding/base64"

type DisconnectCause struct {
	Delimiter uint32
	Cause     uint32
}

const (
	DisconnectCauseDelimiter                     uint32 = 0xdeadbeef
	DisconnectCauseNone                          uint32 = 0
	DisconnectCauseProtocolRequestedNotSupported uint32 = 1
	DisconnectCauseNotEnoughSecurityRequested    uint32 = 2
	DisconnectCauseClientKeyNotRecognised        uint32 = 3
	DisconnectCausePuzzleNotSolved               uint32 = 4
	DisconnectCauseMyMistake                     uint32 = 0xffff

	SharedSecretRequestTypeKEMAndPotp uint8 = 0
)

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
	RequestType      uint8 // fix=0, fix proposal of keys and Potps, open to make an unbounded list in the future
	KeyIdPreferred   [256 / 8]byte
	KeyIdStillValid  [256 / 8]byte
	PotpIdPreferred  [256 / 8]byte
	PotpIdStillValid [256 / 8]byte
}

func (s *SharedSecretRequest) KeyIdPreferredAsString() string {
	return base64.StdEncoding.EncodeToString(s.KeyIdPreferred[:])
}
func (s *SharedSecretRequest) KeyIdStillValidAsString() string {
	return base64.StdEncoding.EncodeToString(s.KeyIdStillValid[:])
}
func (s *SharedSecretRequest) PotpIdPreferredAsString() string {
	return base64.StdEncoding.EncodeToString(s.PotpIdPreferred[:])
}
func (s *SharedSecretRequest) PotpIdStillValidAsString() string {
	return base64.StdEncoding.EncodeToString(s.PotpIdStillValid[:])
}

// Message used in the wire, describes how many 'SecretsCount' of size 'SecretSize' to read.
type SharedSecretBundleDescriptionResponse struct {
	PubKeyIdUsed [256 / 8]byte
	PotpIdUsed   [256 / 8]byte
	PotpOffset   uint64
	SecretsCount uint8
	SecretSize   uint16
}

type SharedSecret struct {
	Shared [][]byte
}
