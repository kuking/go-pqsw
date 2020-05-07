package msg

import "encoding/base64"

type DisconnectCause struct {
	Delimiter uint32
	Cause     uint32
}

const DisconnectCauseDelimiter uint32 = 0xdeadbeef
const DisconnectCauseNone uint32 = 0
const DisconnectCauseProtocolRequestedNotSupported uint32 = 1
const DisconnectCauseNotEnoughSecurityRequested uint32 = 2
const DisconnectCauseClientKeyNotRecognised uint32 = 3
const DisconnectCausePuzzleNotSolved uint32 = 4
const DisconnectCauseMyMistake uint32 = 0xffff

type ClientHello struct {
	Protocol uint32
	WireType uint32
	KeyId    [256 / 8]byte
	PskId    [256 / 8]byte
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
