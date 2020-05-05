package wire

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/google/logger"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/pkg/errors"
	"io"
	"log"
	"net"
	"time"
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

	knockKnockMsg := msg.KnockKnock{}
	err := binary.Read(conn, binary.LittleEndian, &knockKnockMsg)
	if terminateHandshakeOnError(conn, err, "Reading client KnockKnock message") {
		return
	}
	err = checkKnockKnockMsg(&knockKnockMsg, cfg)
	if terminateHandshakeOnError(conn, err, "checking client KnockKnock message") {
		return
	}

	hashReq, err := sendHashRequest(conn, cfg)
	if terminateHandshakeOnError(conn, err, "sending PuzzleRequest message") {
		return
	}
	fmt.Printf("WIP: Server sent PuzzleRequest: %v\n", hashReq)

	time.Sleep(1 * time.Second) //Temporary until the whole thing is finished
}

func sendHashRequest(conn net.Conn, cfg *config.Config) (*msg.PuzzleRequest, error) {
	randomBytes := make([]byte, 64)
	n, err := io.ReadFull(rand.Reader, randomBytes)
	if err != nil {
		return nil, err
	}
	if n != 64 {
		return nil, errors.New("Could not get enough randomness")
	}
	var payload [64]byte
	copy(payload[:], randomBytes)
	req := msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ,
		Body:   payload,
		Param:  msg.SHA512LZParam,
	}
	err = binary.Write(conn, binary.LittleEndian, req)
	return &req, err
}

func checkKnockKnockMsg(knock *msg.KnockKnock, cfg *config.Config) error {
	if knock.ProtocolVersion != 1 {
		return errors.Errorf("Protocol version not supported: %v", knock.ProtocolVersion)
	}
	if knock.WireType != 1 {
		return errors.Errorf("Wire Type requested not supported: %v", knock.WireType)
	}
	keyId := base64.StdEncoding.EncodeToString(knock.KeyId[:])
	if !cfg.ContainsKeyById(keyId) {
		return errors.Errorf("KeyId not recognized: %v", keyId)
	}
	return nil
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
