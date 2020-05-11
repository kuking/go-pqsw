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

	_, _, serr := challengeWithPuzzle(conn, cfg)
	if terminateHandshakeOnServerError(conn, serr, "challenging client with puzzle") {
		return
	}

	clientHello, serr := receiveAndVerifyClientHello(conn, cfg)
	if terminateHandshakeOnServerError(conn, serr, "reading and checking client ClientHello message") {
		return
	}

	cliShare, srvShare, err := negotiateSharedSecrets(conn, cfg, clientHello)
	if terminateHandshakeOnError(conn, err, "negotiating shared secrets") {
		return
	}
	fmt.Print(cliShare, srvShare)

	// WIP
}

func receiveAndVerifyClientHello(conn net.Conn, cfg *config.Config) (*msg.ClientHello, *ServerError) {
	clientHello := msg.ClientHello{}
	err := binary.Read(conn, binary.LittleEndian, &clientHello)
	if err != nil {
		return nil, ServerErrorWrap(err)
	}
	if clientHello.Protocol != 1 {
		return nil, Disconnect(
			errors.Errorf("protocol version not supported: %v", clientHello.Protocol),
			msg.DisconnectCauseProtocolRequestedNotSupported)
	}
	if clientHello.WireType != msg.ClientHelloWireTypeSimpleAES256 && clientHello.WireType != msg.ClientHelloWireTypeTripleAES256 {
		return nil, Disconnect(
			errors.Errorf("wire type requested not supported: %v", clientHello.WireType),
			msg.DisconnectCauseProtocolRequestedNotSupported)
	}
	if cfg.RequireTripleAES256 && clientHello.WireType != msg.ClientHelloWireTypeTripleAES256 {
		return nil, Disconnect(
			errors.Errorf("not enough security requested"),
			msg.DisconnectCauseNotEnoughSecurityRequested)
	}
	if !cfg.ContainsKeyById(clientHello.KeyIdAsString()) {
		return nil, Disconnect(
			errors.Errorf("keyid not recognized: %v", clientHello.KeyIdAsString()),
			msg.DisconnectCauseClientKeyNotRecognised)
	}
	return &clientHello, nil
}

func challengeWithPuzzle(conn net.Conn, cfg *config.Config) (*msg.PuzzleRequest, *msg.PuzzleResponse, *ServerError) {

	var payload [64]byte
	copy(payload[:], cryptoutil.RandBytes(64))
	req := msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ,
		Body:   payload,
		Param:  uint16(cfg.PuzzleDifficulty),
	}
	err := binary.Write(conn, binary.LittleEndian, req)

	res := msg.PuzzleResponse{}
	err = binary.Read(conn, binary.LittleEndian, &res)
	if err != nil {
		return nil, nil, ServerErrorWrap(err)
	}
	if !sha512lz.Verify(req.Body, res.Response, int(req.Param)) {
		return &req, &res, Disconnect(
			errors.New("client did not pass the puzzle challenge"),
			msg.DisconnectCausePuzzleNotSolved)
	}
	return &req, &res, nil
}

func negotiateSharedSecrets(conn net.Conn, cfg *config.Config, clientHello *msg.ClientHello) (
	clientShare *msg.SharedSecret,
	serverShare *msg.SharedSecret,
	err error) {

	serverKey, err := cfg.GetKeyByID(cfg.ServerKey)
	if err != nil {
		return clientShare, serverShare, errors.Wrap(err, "ServerKey specified by configuration not found")
	}
	clientKey, err := cfg.GetKeyByID(clientHello.KeyIdAsString())
	if err != nil {
		return clientShare, serverShare, err
	}

	//XXX	kemsRequiredPerSide := (calculateTotalKEMsRequired(serverKey.GetKeyType(), clientHello.WireType) + 1) / 2
	shrSecretReq := msg.SharedSecretRequest{
		RequestType:      0,
		KeyIdPreferred:   serverKey.GetKeyIdAs32Byte(),
		KeyIdStillValid:  [32]byte{},
		PotpIdPreferred:  [32]byte{},
		PotpIdStillValid: [32]byte{},
	}
	err = binary.Write(conn, binary.LittleEndian, shrSecretReq)
	if err != nil {
		return clientShare, serverShare, err
	}

	clientShare, err = readSharedSecret(conn, serverKey, clientKey)
	if err != nil {
		return clientShare, serverShare, err
	}

	//serverShare, err = createAndSendSharedSecret(conn, serverKey, clientKey)
	//if err != nil {
	//	return clientShare, serverShare, err
	//}

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
	case msg.ClientHelloWireTypeSimpleAES256:
		wireBytes = 256 / 8
	case msg.ClientHelloWireTypeTripleAES256:
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
	logger.Infof("remote: '%v' terminated with error: '%v', while: '%v'", conn.RemoteAddr(), err, explanation)
	err2 := conn.Close()
	if err2 != nil {
		logger.Infof("could not close connection %v", conn)
	}
	return true
}

func terminateHandshakeOnServerError(conn net.Conn, serr *ServerError, explanation string) bool {
	if serr == nil {
		return false
	}
	if serr.disconnectCause != msg.DisconnectCauseNone {
		logger.Infof("remote: '%v' disconnecting with verbose cause: %v", conn.RemoteAddr(), serr.disconnectCause)
		cause := msg.DisconnectCause{
			Delimiter: msg.DisconnectCauseDelimiter,
			Cause:     serr.disconnectCause,
		}
		err := binary.Write(conn, binary.LittleEndian, cause)
		if err != nil {
			logger.Infof("remote '%v' could not send last disconnect message due to: %v", conn.RemoteAddr(), err)
		}
	}
	return terminateHandshakeOnError(conn, serr.err, explanation)
}

// ------------------------------------------------------------------------------------------------------------------

type ServerError struct {
	err             error
	disconnectCause uint32
}

func ServerErrorWrap(err error) *ServerError {
	return &ServerError{
		err:             err,
		disconnectCause: msg.DisconnectCauseNone,
	}
}

func Disconnect(err error, cause uint32) *ServerError {
	return &ServerError{
		err:             err,
		disconnectCause: cause,
	}
}
