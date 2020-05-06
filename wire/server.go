package wire

import (
	"encoding/binary"
	"fmt"
	"github.com/google/logger"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"github.com/pkg/errors"
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

	knock, err := receiveAndVerifyKnock(conn, cfg)
	if terminateHandshakeOnError(conn, err, "reading and checking client Knock message") {
		return
	}

	_, _, err = challengeWithPuzzle(conn)
	if terminateHandshakeOnError(conn, err, "challenging client with puzzle") {
		return
	}

	cliShare, srvShare, err := negotiateSharedSecrets(conn, cfg, knock)
	if terminateHandshakeOnError(conn, err, "negotiating shared secrets") {
		return
	}
	fmt.Print(cliShare, srvShare)

	// WIP
}

func receiveAndVerifyKnock(conn net.Conn, cfg *config.Config) (*msg.Knock, error) {
	knock := msg.Knock{}
	err := binary.Read(conn, binary.LittleEndian, &knock)
	if err != nil {
		return nil, err
	}
	if knock.ProtocolVersion != 1 {
		return nil, errors.Errorf("Protocol version not supported: %v", knock.ProtocolVersion)
	}
	if knock.WireType != msg.WireTypeSimpleAES256 && knock.WireType != msg.WireTypeTripleAES256 {
		return nil, errors.Errorf("Wire Type requested not supported: %v", knock.WireType)
	}
	if !cfg.ContainsKeyById(knock.KeyIdAsString()) {
		return nil, errors.Errorf("KeyId not recognized: %v", knock.KeyIdAsString())
	}
	return &knock, nil
}

func challengeWithPuzzle(conn net.Conn) (*msg.PuzzleRequest, *msg.PuzzleResponse, error) {

	var payload [64]byte
	copy(payload[:], cryptoutil.RandBytes(64))
	req := msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ,
		Body:   payload,
		Param:  msg.SHA512LZParam,
	}
	err := binary.Write(conn, binary.LittleEndian, req)

	res := msg.PuzzleResponse{}
	err = binary.Read(conn, binary.LittleEndian, &res)
	if err != nil {
		return nil, nil, err
	}
	if !sha512lz.Verify(req.Body, res.Response, int(req.Param)) {
		return &req, &res, errors.New("Client did not pass the Puzzle challenge")
	}
	return &req, &res, nil
}

func negotiateSharedSecrets(conn net.Conn, cfg *config.Config, knock *msg.Knock) (
	clientShare *msg.SharedSecret,
	serverShare *msg.SharedSecret,
	err error) {

	//FIXME: TODO: SERVER IS USING THE FIRST KEY AVAILABLE
	serverKey := &cfg.Keys[0]
	clientKey, err := cfg.GetKeyByID(knock.KeyIdAsString())
	if err != nil {
		return clientShare, serverShare, err
	}

	kemsRequiredPerSide := (calculateTotalKEMsRequired(serverKey.GetKeyType(), knock.WireType) + 1) / 2
	shrSecretReq := msg.SharedSecretRequest{
		KeyId:  serverKey.GetKeyIdAs32Byte(),
		Counts: kemsRequiredPerSide,
	}
	err = binary.Write(conn, binary.LittleEndian, shrSecretReq)
	if err != nil {
		return clientShare, serverShare, err
	}

	clientShare, err = readSharedSecret(conn, serverKey, clientKey)
	if err != nil {
		return clientShare, serverShare, err
	}

	//kem, err := serverKey.GetKemSike()
	//if err != nil {
	//	return nil, nil, err
	//}

	//var cipherText = make([]byte, kem.CiphertextSize())
	//var sharedSecret = make([]byte, kem.SharedSecretSize())
	//err = kem.Encapsulate(cipherText, sharedSecret, cli)
	//if err != nil {
	//	return clientShare, serverShare, err
	//}
	//
	return clientShare, serverShare, err
}

func calculateTotalKEMsRequired(keyType cryptoutil.KeyType, wireType uint32) uint16 {
	kemSize := 0
	switch keyType {
	case cryptoutil.KeyTypeSidhFp503:
		kemSize = cryptoutil.KeyTypeSidhFp503KemSize
	case cryptoutil.KeyTypeSidhFp751:
		kemSize = cryptoutil.KeyTypeSidhFp751KemSize
	default:
		panic("I don't know about this key, but this should have been catch earlier")
	}
	wireBytes := 0
	switch wireType {
	case msg.WireTypeSimpleAES256:
		wireBytes = 256 / 8
	case msg.WireTypeTripleAES256:
		wireBytes = 256 * 3 / 8
	default:
		panic("i can not recognise this wire type, which should have been catch already")
	}
	return uint16((wireBytes + 1) / kemSize)
}

func readSharedSecret(conn net.Conn, receiver *config.Key, sender *config.Key) (res *msg.SharedSecret, err error) {
	bundleDesc := msg.SharedSecretBundleDescriptionResponse{}
	err = binary.Read(conn, binary.LittleEndian, &bundleDesc)
	if err != nil {
		return res, err
	}
	res = &msg.SharedSecret{
		Shared: make([][]byte, bundleDesc.SecretsCount),
	}
	kem, err := receiver.GetKemSike()
	if err != nil {
		return res, err
	}
	for count := 0; count < int(bundleDesc.SecretsCount); count++ {
		cipherText := make([]byte, bundleDesc.SecretSize)
		err = binary.Read(conn, binary.LittleEndian, cipherText)
		if err != nil {
			return res, err
		}
		err = kem.Decapsulate(res.Shared[count], receiver.GetSidhPrivateKey(), sender.GetSidhPublicKey(), cipherText)
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
