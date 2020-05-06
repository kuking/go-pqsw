package wire

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/cloudflare/circl/dh/sidh"
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

	knock, err := receiveAndVerifyKnockKnock(conn, cfg)
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

func receiveAndVerifyKnockKnock(conn net.Conn, cfg *config.Config) (*msg.Knock, error) {
	knockKnock := msg.Knock{}
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
		return &req, &res, errors.New("Client did not pass Puzzle challenge.")
	}
	return &req, &res, nil
}

func negotiateSharedSecrets(conn net.Conn, cfg *config.Config, knock *msg.Knock) (clientShare *msg.SharedSecretResponse, serverShare *msg.SharedSecretRequest, err error) {

	//FIXME: TODO: SERVER IS USING THE FIRST KEY AVAILABLE
	serverKey := cfg.Keys[0]
	clientKey, err := cfg.GetKeyByID(knock.KeyIdAsString())
	if err != nil {
		return clientShare, serverShare, err
	}

	shrSecretReq := msg.SharedSecretRequest{
		KeyId: serverKey.GetKeyIdAs32Byte(),
	}
	if knock.WireType == msg.WireTypeSimpleAES256 {
		shrSecretReq.Bits = 128
	} else if knock.WireType == msg.WireTypeTripleAES256 {
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

	//serverKeyPrivate := cryptoutil.SidhPrivateKeyFromString(serverKey.Pvt)
	clientKeyPublic := cryptoutil.SidhPublicKeyFromString(clientKey.Pub)

	var kem *sidh.KEM
	if serverKey.GetKeyType() == cryptoutil.KeyTypeSidhFp503 {
		kem = sidh.NewSike503(rand.Reader)
	} else if serverKey.GetKeyType() == cryptoutil.KeyTypeSidhFp751 {
		kem = sidh.NewSike751(rand.Reader)
	} else {
		return clientShare, serverShare, errors.New("can not create kem for key")
	}
	var cipherText = make([]byte, kem.CiphertextSize())
	var sharedSecret = make([]byte, kem.SharedSecretSize())

	err = kem.Encapsulate(cipherText, sharedSecret, clientKeyPublic)
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
