package wire

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"github.com/pkg/errors"
	"net"
)

const MaxPuzzleClientWouldAccept = 20

func ClientHandshake(conn net.Conn, cfg *config.Config) (wire *SecureWire, err error) {
	err = answerPuzzle(conn)
	if terminateHandshakeOnError(conn, err, "answering puzzle") {
		return
	}
	clientKey, err := cfg.GetKeyByCN(cfg.PreferredKeyCN)
	if terminateHandshakeOnError(conn, err, "retrieving client key from configuration") {
		return
	}
	err = sendHello(conn, cfg, clientKey)
	if terminateHandshakeOnError(conn, err, "sending client hello") {
		return
	}
	shareSecretReq, symmetricKeySize, err := readSharedSecretRequest(conn, cfg)
	if terminateHandshakeOnError(conn, err, "receiving server share secret request") {
		return
	}
	serverKey, err := cfg.GetKeyByID(shareSecretReq.KeyIdPreferredAsString())
	if terminateHandshakeOnError(conn, err, fmt.Sprintf("received server key in request unknown: %v", shareSecretReq.KeyIdPreferredAsString())) {
		return
	}
	potp, err := cfg.GetPotpByCN(cfg.PreferredPotpCN)
	if terminateHandshakeOnError(conn, err, "could not retrieve server potp from config") {
		return
	}
	clientShare, serr := sendSharedSecret(conn, serverKey, potp, symmetricKeySize)
	if serr != nil && terminateHandshakeOnError(conn, serr.err, "sending shared secret to server") {
		err = serr.err
		return
	}
	serverShare, serr := readSharedSecret(conn, clientKey, cfg, symmetricKeySize)
	if serr != nil && terminateHandshakeOnError(conn, serr.err, "reading shared secret from server") {
		err = serr.err
		return
	}
	keysBytes := mixSharedSecretsForKey(serverShare, clientShare, symmetricKeySize)
	//fmt.Println("Client session key (debug, disable in prod):", cryptoutil.EncB64(keysBytes))
	wire, err = BuildSecureWire(keysBytes, conn, clientKey.IdAs32Byte(), serverKey.IdAs32Byte())
	if terminateHandshakeOnError(conn, err, "establishing secure_wire") {
		return
	}
	err = clientHandshakeOverSecureWire(wire)
	if terminateHandshakeOnError(conn, err, "handshaking over secure wire") {
		return
	}
	return
}

func clientHandshakeOverSecureWire(sw *SecureWire) error {
	goodRead := make([]byte, 4)
	n, err := sw.Read(goodRead)
	if n != len(msg.SecureWireGoodState) || bytes.Compare(msg.SecureWireGoodState, goodRead) != 0 {
		err = errors.New("read good secure_write message invalid")
	}
	if err != nil {
		return err
	}
	n, err = sw.Write(msg.SecureWireGoodState)
	if n != len(msg.SecureWireGoodState) {
		err = errors.New("could not write good secure_wire message")
	}
	return err
}

func readSharedSecretRequest(conn net.Conn, cfg *config.Config) (req *msg.SharedSecretRequest, symmetricKeySize int, err error) {
	req = &msg.SharedSecretRequest{}
	err = binary.Read(conn, binary.LittleEndian, req)
	if err != nil {
		return
	}
	if req.RequestType != msg.SharedSecretRequestTypeKEMAndPotp {
		err = errors.Errorf("unknown shared request type provided=%v", req.RequestType)
		return
	}
	_, err = cfg.GetKeyByID(req.KeyIdPreferredAsString())
	if err != nil {
		err = errors.Wrap(err, "key requested by server in server share request unknown")
		return
	}
	if req.WireType == msg.WireTypeSimpleAES256 && cfg.TripleAES256 == config.TripleAES256Required {
		err = errors.New("server insist on SimpleAES256 when we required TripleAES256.")
		return
	}
	if req.WireType == msg.WireTypeTripleAES256 && cfg.TripleAES256 == config.TripleAES256Disabled {
		err = errors.New("server insist on TripleAES256 when we required SingleAES256 and it is disabled by config, so we can not proceed.")
		return
	}
	symmetricKeySize = 256/8 + 96/8
	if req.WireType == msg.WireTypeTripleAES256 {
		symmetricKeySize *= 3
	}
	return
}

func sendHello(conn net.Conn, cfg *config.Config, clientKey *config.Key) (err error) {
	clientHello := msg.ClientHello{
		Protocol: msg.ClientHelloProtocol,
		KeyId:    clientKey.IdAs32Byte(),
		WireType: msg.WireTypeSimpleAES256,
	}
	if cfg.TripleAES256 == config.TripleAES256Required {
		clientHello.WireType = msg.WireTypeTripleAES256
	} else if cfg.TripleAES256 == config.TripleAES256Allowed {
		clientHello.WireType = msg.WireTypeTripleAES256Optional
	}
	return binary.Write(conn, binary.LittleEndian, &clientHello)
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
