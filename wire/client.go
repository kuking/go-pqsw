package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
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

	err = sendHello(conn, clientKey)
	if terminateHandshakeOnError(conn, err, "sending client hello") {
		return
	}

	keySize := 123
	kem, err := clientKey.GetKemSike()
	if terminateHandshakeOnError(conn, err, "obtaining kem to negotiate shared secrets") {
		return
	}

	_, serr := readSharedSecret(conn, clientKey, cfg, keySize, kem)
	if serr != nil && terminateHandshakeOnError(conn, serr.err, "reading shared secret from server") {
		return
	}

}

func sendHello(conn net.Conn, clientKey *config.Key) error {
	clientHello := msg.ClientHello{
		Protocol: msg.ClientHelloProtocol,
		WireType: msg.ClientHelloWireTypeSimpleAES256,
		KeyId:    clientKey.GetKeyIdAs32Byte(),
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
