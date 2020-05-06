package wire

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
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
	if terminateHandshakeOnError(conn, err, "reading and checking client KnockKnock message") {
		return
	}

	_, _, err = challengeWithPuzzle(conn)
	if terminateHandshakeOnError(conn, err, "challenging client with puzzle") {
		return
	}

	cliShare, srvShare, err := negotiateSharedSecrets(conn, cfg, knockKnock.WireType)
	if terminateHandshakeOnError(conn, err, "challenging client with puzzle") {
		return
	}

	fmt.Print(cliShare, srvShare)

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
	if knockKnock.WireType != msg.WireTypeSimpleAES256 && knockKnock.WireType != msg.WireTypeTripleAES256 {
		return nil, errors.Errorf("Wire Type requested not supported: %v", knockKnock.WireType)
	}
	keyId := base64.StdEncoding.EncodeToString(knockKnock.KeyId[:])
	if !cfg.ContainsKeyById(keyId) {
		return nil, errors.Errorf("KeyId not recognized: %v", keyId)
	}
	return &knockKnock, nil
}

func challengeWithPuzzle(conn net.Conn) (*msg.PuzzleRequest, *msg.PuzzleResponse, error) {
	var payload [64]byte
	n, err := io.ReadFull(rand.Reader, payload[:])
	if err != nil {
		return nil, nil, err
	}
	if n != 64 {
		return nil, nil, errors.New("Could not get enough randomness")
	}
	req := msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ,
		Body:   payload,
		Param:  msg.SHA512LZParam,
	}
	err = binary.Write(conn, binary.LittleEndian, req)

	res := msg.PuzzleResponse{}
	err = binary.Read(conn, binary.LittleEndian, &res)
	if err != nil {
		return nil, nil, err
	}
	if !sha512lz.Verify(req.Body, res.Response, int(req.Param)) {
		return &req, &res, errors.New("Client did not pass Puzzle challenge.")
	}
	return &req, &res, nil
}

func negotiateSharedSecrets(conn net.Conn, cfg *config.Config, wireType uint32) (clientShare *msg.SharedSecretResponse, serverShare *msg.SharedSecretRequest, err error) {

	//FIXME: TODO: SERVER IS USING THE FIRST KEY AVAILABLE
	serverKey := cfg.Keys[0]

	shrSecretReq := msg.SharedSecretRequest{
		KeyId: serverKey.GetKeyIdAs32Byte(),
	}
	if wireType == msg.WireTypeSimpleAES256 {
		shrSecretReq.Bits = 128
	} else if wireType == msg.WireTypeTripleAES256 {
		shrSecretReq.Bits = 256 * 3 / 2
	} else {
		panic("I don't know how many bits I need for that WireType key.")
	}
	err = binary.Write(conn, binary.LittleEndian, shrSecretReq)
	if err != nil {
		return clientShare, serverShare, err
	}
	clientShare, err = readSharedSecret(conn)
	if err != nil {
		return clientShare, serverShare, err
	}

	return clientShare, serverShare, err
}

func readSharedSecret(conn net.Conn) (res *msg.SharedSecretResponse, err error) {
	bundle := msg.SharedSecretBundleDescriptionResponse{}
	err = binary.Read(conn, binary.LittleEndian, &bundle)
	if err != nil {
		return res, err
	}
	res = &msg.SharedSecretResponse{
		Shared: make([][]byte, bundle.SecretsCount),
	}
	for count := 0; count < int(bundle.SecretsCount); count++ {
		res.Shared[count] = make([]byte, bundle.SecretSize)
		err = binary.Read(conn, binary.LittleEndian, &res.Shared[count])
		if err != nil {
			return res, err
		}
	}
	return res, err
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
