package wire

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"github.com/google/logger"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"github.com/pkg/errors"
	"io"
	"log"
	"net"
)

func closeListener(l net.Listener) {
	err := l.Close()
	if err != nil {
		log.Fatal(err)
	}
}

func Listen(hostPort string, cfg *config.Config) error {
	l, err := net.Listen("tcp", hostPort)
	if err != nil {
		return err
	}
	defer closeListener(l)
	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Infof("Could not accept connection: %v", err)
		} else {
			go newClientHandshake(conn, cfg)
		}

	}
}

func newClientHandshake(conn net.Conn, cfg *config.Config) {

	knockKnock, err := receiveAndVerifyKnockKnock(conn, cfg)
	if terminateHandshakeOnError(conn, err, "Reading and checking client KnockKnock message") {
		return
	}

	puzzleReq, err := sendPuzzleRequest(conn)
	if terminateHandshakeOnError(conn, err, "sending PuzzleRequest message") {
		return
	}
	_, err = receiveAndVerifyPuzzleResponse(conn, puzzleReq)
	if terminateHandshakeOnError(conn, err, "receiving PuzzleResponse message and verifying it") {
		return
	}
	_, err = sendSharedSecretRequest(conn, cfg, knockKnock.WireType)
	if terminateHandshakeOnError(conn, err, "requesting Shared Secret") {
		return
	}

	// WIP
}

func receiveAndVerifyKnockKnock(conn net.Conn, cfg *config.Config) (*msg.KnockKnock, error) {
	knockKnock := msg.KnockKnock{}
	err := binary.Read(conn, binary.LittleEndian, &knockKnock)
	if err != nil {
		return nil, err
	}
	if knockKnock.ProtocolVersion != 1 {
		return nil, errors.Errorf("Protocol version not supported: %v", knockKnock.ProtocolVersion)
	}
	if knockKnock.WireType != msg.WireType_SimpleAES256 && knockKnock.WireType != msg.WireType_TripleAES256 {
		return nil, errors.Errorf("Wire Type requested not supported: %v", knockKnock.WireType)
	}
	keyId := base64.StdEncoding.EncodeToString(knockKnock.KeyId[:])
	if !cfg.ContainsKeyById(keyId) {
		return nil, errors.Errorf("KeyId not recognized: %v", keyId)
	}
	return &knockKnock, nil
}

func sendPuzzleRequest(conn net.Conn) (*msg.PuzzleRequest, error) {
	var payload [64]byte
	n, err := io.ReadFull(rand.Reader, payload[:])
	if err != nil {
		return nil, err
	}
	if n != 64 {
		return nil, errors.New("Could not get enough randomness")
	}
	req := msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ,
		Body:   payload,
		Param:  msg.SHA512LZParam,
	}
	err = binary.Write(conn, binary.LittleEndian, req)
	return &req, err
}

func receiveAndVerifyPuzzleResponse(conn net.Conn, req *msg.PuzzleRequest) (*msg.PuzzleResponse, error) {
	res := msg.PuzzleResponse{}
	err := binary.Read(conn, binary.LittleEndian, &res)
	if err != nil {
		return nil, err
	}
	if !sha512lz.Verify(req.Body, res.Response, int(req.Param)) {
		return &res, errors.New("Client did not pass Puzzle challenge.")
	}
	return &res, nil
}

func sendSharedSecretRequest(conn net.Conn, cfg *config.Config, wireType uint32) (*msg.SharedSecretRequest, error) {
	//FIXME: TODO: SERVER IS USING THE FIRST KEY AVAILABLE
	shrSecretReq := msg.SharedSecretRequest{
		KeyId: cfg.Keys[0].GetKeyIdAs32Byte(),
	}
	if wireType == msg.WireType_SimpleAES256 {
		shrSecretReq.Bits = 128
	} else if wireType == msg.WireType_TripleAES256 {
		shrSecretReq.Bits = 256 * 3 / 2
	} else {
		panic("I don't know how many bits I need for that WireType key.")
	}

	err := binary.Write(conn, binary.LittleEndian, shrSecretReq)
	if err != nil {
		return nil, err
	}
	return &shrSecretReq, nil
}

func terminateHandshakeOnError(conn net.Conn, err error, explanation string) bool {
	if err == nil {
		return false
	}
	logger.Infof("Remote: '%v' terminated with error: '%v', while: '%v'", conn.RemoteAddr(), err, explanation)
	err2 := conn.Close()
	if err2 != nil {
		logger.Infof("Could not close connection %v", conn)
	}
	return true
}
