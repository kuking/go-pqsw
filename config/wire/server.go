package wire

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/google/logger"
	"github.com/kuking/go-pqsw/config"
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

	knockKnockMsg := KnockKnock{}
	err := binary.Read(conn, binary.LittleEndian, &knockKnockMsg)
	if terminateHandshakeOnError(conn, err, "Reading client KnockKnock message") {
		return
	}
	err = checkKnockKnockMsg(&knockKnockMsg, cfg)
	if terminateHandshakeOnError(conn, err, "checking client KnockKnock message") {
		return
	}

	hashReq, err := sendHashRequest(conn)
	if terminateHandshakeOnError(conn, err, "sending HashRequest message") {
		return
	}
	fmt.Printf("Server sent HashRequest: %v\n", hashReq)

}

func sendHashRequest(conn net.Conn) (*HashRequest, error) {
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
	req := HashRequest{
		KeyDerivationAlgo: HashRequestScrypt,
		Payload:           payload,
		Iterations:        10000,
	}
	err = binary.Write(conn, binary.LittleEndian, req)
	return &req, err
}

func checkKnockKnockMsg(knock *KnockKnock, cfg *config.Config) error {
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
	logger.Infof("Remote: %v terminated with error: %v, while: %v", conn.RemoteAddr(), err, explanation)
	err2 := conn.Close()
	if err2 != nil {
		logger.Infof("Could not close connection %v", conn)
	}
	return true
}
