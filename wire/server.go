package wire

import (
	"bytes"
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

	_, _, serr := challengeWithPuzzle(conn, cfg)
	if terminateHandshakeOnServerError(conn, serr, "challenging client with puzzle") {
		return
	}

	clientHello, serr := receiveAndVerifyClientHello(conn, cfg)
	if terminateHandshakeOnServerError(conn, serr, "reading and checking client ClientHello message") {
		return
	}

	cliShare, srvShare, serr := negotiateSharedSecrets(conn, cfg, clientHello)
	if terminateHandshakeOnServerError(conn, serr, "negotiating shared secrets") {
		return
	}

	keySize := calculateKeySize(clientHello)
	keysBytes := mixSharedSecretsForKey(srvShare, cliShare, keySize)

	sw, err := NewSecureWireAES256CGM(keysBytes[0:32], keysBytes[32:32+12], conn)
	if terminateHandshakeOnError(conn, err, "establishing secure wire") {
		return
	}

	fmt.Printf("server' key: %v\n", cryptoutil.EncB64(keysBytes))
	serr = handshakeOverSecureWire(sw)
	if terminateHandshakeOnServerError(conn, serr, "while handshaking over secure_wire") {
		return
	}

	fmt.Println("Server has established a secure connection")

}

func handshakeOverSecureWire(sw *SecureWire) *ServerError {
	n, err := sw.Write(msg.SecureWireGoodState)
	if n != len(msg.SecureWireGoodState) {
		err = errors.New("could not write good secure_wire message")
	}
	if err != nil {
		return Disconnect(err, msg.DisconnectCauseNone)
	}
	goodRead := make([]byte, 4)
	n, err = sw.Read(goodRead)
	if n != len(msg.SecureWireGoodState) || bytes.Compare(msg.SecureWireGoodState, goodRead) != 0 {
		err = errors.New("read good secure_write message invalid")
	}
	if err != nil {
		return Disconnect(err, msg.DisconnectCauseNone)
	}
	return nil
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
			errors.Errorf("counter party keyid not recognized: %v", clientHello.KeyIdAsString()),
			msg.DisconnectCauseCounterpartyKeyIdNotRecognised)
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
	serr *ServerError) {

	keySize := calculateKeySize(clientHello)

	serverKey, err := cfg.GetKeyByID(cfg.ServerKey)
	if err != nil {
		return clientShare, serverShare,
			Disconnect(errors.Wrap(err, "serverKey specified by configuration not found"), msg.DisconnectCauseSeverMisconfiguration)
	}
	clientKey, err := cfg.GetKeyByID(clientHello.KeyIdAsString())
	if err != nil {
		// this should never happen has it has been verified by receiveAndVerifyClientHello()
		return clientShare, serverShare,
			Disconnect(errors.Wrap(err, "clientKey specified not found"), msg.DisconnectCauseCounterpartyKeyIdNotRecognised)
	}
	serverPotp, err := cfg.GetPotpByID(cfg.ServerPotp)
	if err != nil {
		return clientShare, serverShare,
			Disconnect(errors.Wrap(err, "serverPotp specified by configuration not found"), msg.DisconnectCauseSeverMisconfiguration)
	}

	shrSecretReq := msg.SharedSecretRequest{
		RequestType: 0,
		KeyId:       serverKey.GetKeyIdAs32Byte(),
	}
	err = binary.Write(conn, binary.LittleEndian, shrSecretReq)
	if err != nil {
		return clientShare, serverShare, Disconnect(err, msg.DisconnectCauseNone)
	}

	kem, err := serverKey.GetKemSike()
	if err != nil {
		return clientShare, serverShare,
			Disconnect(errors.Wrap(err, "could not generate kem using server key"), msg.DisconnectCauseSeverMisconfiguration)
	}

	clientShare, serr = readSharedSecret(conn, serverKey, cfg, keySize, kem)
	if serr != nil {
		return clientShare, serverShare, serr
	}

	serverShare, serr = sendSharedSecret(conn, clientKey, serverPotp, keySize, kem)
	if serr != nil {
		return clientShare, serverShare, serr
	}

	return clientShare, serverShare, nil
}

func sendSharedSecret(conn net.Conn, receiver *config.Key, potp *config.Potp, keySize int, kem *sidh.KEM) (res *msg.SharedSecret, serr *ServerError) {
	potpBytes, potpOfs := potp.PickOTP(keySize)

	secretsCount := calculateSharedSecretsCount(kem, keySize)

	fmt.Printf("server sent: otp ofs=%v len=%v val=%v\n", potpOfs, keySize, base64.StdEncoding.EncodeToString(potpBytes))

	res = &msg.SharedSecret{
		Otp:    potpBytes,
		Shared: make([][]byte, secretsCount),
	}
	bundleDesc := msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   potp.GetPotpIdAs32Byte(),
		PotpOffset:   potpOfs,
		SecretsCount: uint8(secretsCount),
		SecretSize:   uint16(kem.CiphertextSize()),
	}
	err := binary.Write(conn, binary.LittleEndian, &bundleDesc)
	if err != nil {
		return res, Disconnect(err, msg.DisconnectCauseNone)
	}

	for secretNo := 0; secretNo < secretsCount; secretNo++ {
		res.Shared[secretNo] = make([]byte, kem.SharedSecretSize())
		ciphertext := make([]byte, kem.CiphertextSize())
		err = kem.Encapsulate(ciphertext, res.Shared[secretNo], receiver.GetSidhPublicKey())
		if err != nil {
			return res, Disconnect(err, msg.DisconnectCauseSeverMisconfiguration)
		}
		err = binary.Write(conn, binary.LittleEndian, ciphertext)
		if err != nil {
			return res, Disconnect(err, msg.DisconnectCauseNone)
		}
		fmt.Printf("server sent: secret[%v] %v (cipher: %v)\n", secretNo, cryptoutil.EncB64(res.Shared[secretNo]), cryptoutil.EncB64(ciphertext))
	}

	return res, nil
}

func readSharedSecret(conn net.Conn, receiver *config.Key, cfg *config.Config, keySize int, kem *sidh.KEM) (res *msg.SharedSecret, serr *ServerError) {
	bundleDesc := msg.SharedSecretBundleDescriptionResponse{}
	err := binary.Read(conn, binary.LittleEndian, &bundleDesc)
	if err != nil {
		return res, Disconnect(err, msg.DisconnectCauseNone)
	}

	if int(bundleDesc.SecretSize) != kem.CiphertextSize() {
		return nil, Disconnect(
			errors.New(fmt.Sprintf("client secret-size not the expected to be provided=%v, expected=%v",
				bundleDesc.SecretSize, kem.CiphertextSize())),
			msg.DisconnectCauseNotEnoughSecurityRequested)
	}

	if bundleDesc.SecretsCount == 0 || bundleDesc.SecretsCount > 10 {
		return nil, Disconnect(
			errors.New(fmt.Sprintf("client secret count out of range (0<n=<10), received: %v", bundleDesc.SecretsCount)),
			msg.DisconnectCauseNotEnoughSecurityRequested)
	}

	secretsCount := calculateSharedSecretsCount(kem, keySize)
	if int(bundleDesc.SecretsCount) != secretsCount {
		return nil, Disconnect(
			errors.New(fmt.Sprintf("client secret count out invalid, for current keys it should be: %v, received: %v", secretsCount, bundleDesc.SecretsCount)),
			msg.DisconnectCauseNotEnoughSecurityRequested)
	}

	otp, err := cfg.GetPotpByID(bundleDesc.PotpIdAsString())
	if err != nil {
		return res,
			Disconnect(errors.WithMessagef(err, "potp provided by not recognised, id=%v", bundleDesc.PotpIdAsString()),
				msg.DisconnectCausePotpNotRecognised)
	}
	otpBytes, err := otp.ReadOTP(keySize, bundleDesc.PotpOffset)
	if err != nil {
		return res, Disconnect(err, msg.DisconnectCauseSeverMisconfiguration)
	}
	fmt.Printf("server recv: otp ofs=%v size=%v val=%v\n", bundleDesc.PotpOffset, 32, base64.StdEncoding.EncodeToString(otpBytes))

	res = &msg.SharedSecret{
		Otp:    otpBytes,
		Shared: make([][]byte, bundleDesc.SecretsCount),
	}
	for count := 0; count < int(bundleDesc.SecretsCount); count++ {
		cipherText := make([]byte, bundleDesc.SecretSize)
		res.Shared[count] = make([]byte, kem.SharedSecretSize())
		err = binary.Read(conn, binary.LittleEndian, cipherText)
		if err != nil {
			return res, Disconnect(err, msg.DisconnectCauseNone)
		}
		err = kem.Decapsulate(res.Shared[count], receiver.GetSidhPrivateKey(), receiver.GetSidhPublicKey(), cipherText)
		fmt.Printf("server recv: secret[%v] %v (cipher: %v)\n", count, cryptoutil.EncB64(res.Shared[count]), cryptoutil.EncB64(cipherText))
		if err != nil {
			return res, Disconnect(err, msg.DisconnectCauseNotEnoughSecurityRequested)
		}
	}
	return res, nil
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
		logger.Infof("remote: '%v' disconnecting with verbose cause: %v (%v)",
			conn.RemoteAddr(), msg.DisconnectCauseString[serr.disconnectCause], serr.disconnectCause)
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

func mixSharedSecretsForKey(serverShare *msg.SharedSecret, clientShare *msg.SharedSecret, keySize int) (res []byte) {
	allBytes := cryptoutil.ConcatAll(serverShare.SharesJoined(), clientShare.SharesJoined(), serverShare.Otp, clientShare.Otp)
	res = make([]byte, keySize)
	for i := 0; i < len(allBytes); i++ {
		res[i%keySize] = res[i%keySize] ^ allBytes[i]
	}
	return res
}

func calculateKeySize(clientHello *msg.ClientHello) int {
	keySize := (256 / 8) + (96 / 8)
	if clientHello.WireType == msg.ClientHelloWireTypeTripleAES256 {
		keySize = keySize * 3
	}
	return keySize
}

func calculateSharedSecretsCount(kem *sidh.KEM, keySize int) int {
	secretsCount := keySize / kem.SharedSecretSize()
	if (keySize % kem.SharedSecretSize()) != 0 {
		secretsCount += 1
	}
	return secretsCount
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
