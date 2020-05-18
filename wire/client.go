package wire

import (
	"encoding/binary"
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"github.com/pkg/errors"
	"net"
)

const MaxPuzzleClientWouldAccept = 20

func NewServerHandshake(conn net.Conn, cfg *config.Config) {

	err := answerPuzzle(conn)
	if terminateHandshakeOnError(conn, err, "answering puzzle") {
		return
	}
	clientKey, err := cfg.GetKeyByID(cfg.ClientKey)
	if terminateHandshakeOnError(conn, err, "retrieving client key from configuration") {
		return
	}
	keySize, err := sendHello(conn, clientKey)
	if terminateHandshakeOnError(conn, err, "sending client hello") {
		return
	}
	kem, err := clientKey.GetKemSike()
	if terminateHandshakeOnError(conn, err, "obtaining kem to negotiate shared secrets") {
		return
	}
	shareSecretReq, err := readSharedSecretRequest(conn, cfg)
	if terminateHandshakeOnError(conn, err, "receiving server share secret request") {
		return
	}
	serverKey, err := cfg.GetKeyByID(shareSecretReq.KeyIdPreferredAsString())
	if terminateHandshakeOnError(conn, err, fmt.Sprintf("received server key in request unknown: %v", shareSecretReq.KeyIdPreferredAsString())) {
		return
	}
	potp, err := cfg.GetPotpByID(cfg.ClientPotp)
	if terminateHandshakeOnError(conn, err, "could not retrieve server potp from config") {
		return
	}
	_, serr := sendSharedSecret(conn, serverKey, potp, keySize, kem)
	if serr != nil && terminateHandshakeOnError(conn, serr.err, "sending shared secret to server") {
		return
	}

	//_, serr := readSharedSecret(conn, clientKey, cfg, keySize, kem)
	//if serr != nil && terminateHandshakeOnError(conn, serr.err, "reading shared secret from server") {
	//	return
	//}

}

func readSharedSecretRequest(conn net.Conn, cfg *config.Config) (req *msg.SharedSecretRequest, err error) {
	req = &msg.SharedSecretRequest{}
	err = binary.Read(conn, binary.LittleEndian, req)
	if err != nil {
		return nil, err
	}
	if req.RequestType != msg.SharedSecretRequestTypeKEMAndPotp {
		return nil, errors.Errorf("unknown shared request type provided=%v", req.RequestType)
	}
	_, err = cfg.GetKeyByID(req.KeyIdPreferredAsString())
	if err != nil {
		return nil, errors.Wrap(err, "key requested by server in server share request unknown")
	}
	return req, nil
}

func sendHello(conn net.Conn, clientKey *config.Key) (keySize int, err error) {
	clientHello := msg.ClientHello{
		Protocol: msg.ClientHelloProtocol,
		WireType: msg.ClientHelloWireTypeSimpleAES256,
		KeyId:    clientKey.GetKeyIdAs32Byte(),
	}
	keySize = (256 / 8) + (96 / 8)
	if clientHello.WireType == msg.ClientHelloWireTypeTripleAES256 {
		keySize = keySize * 3
	}
	return keySize, binary.Write(conn, binary.LittleEndian, &clientHello)

}

func answerPuzzle(conn net.Conn) (err error) {
	puzzle := msg.PuzzleRequest{}
	err = binary.Read(conn, binary.LittleEndian, &puzzle)
	if err != nil {
		return
	}
	if puzzle.Puzzle != msg.PuzzleSHA512LZ {
		return errors.New(fmt.Sprintf("can not handle puzzle type provider by server: %v", puzzle.Puzzle))
	}
	if puzzle.Param > MaxPuzzleClientWouldAccept {
		return errors.New(fmt.Sprintf("aledged server might be trying to block me, as 2020 a complexity of %v is considered too big, not calculating anything bigger than %v.",
			puzzle.Param, MaxPuzzleClientWouldAccept))
	}
	response := msg.PuzzleResponse{
		Response: sha512lz.Solve(puzzle.Body, int(puzzle.Param)),
	}
	err = binary.Write(conn, binary.LittleEndian, &response)
	return
}
