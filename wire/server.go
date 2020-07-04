package wire

import (
	"bytes"
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

func Listen(hostPort string, cfg *config.Config, handler func(wire *SecureWire)) error {
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
			go serverHandleNewConnection(conn, cfg, handler)
		}
	}
}

func serverHandleNewConnection(conn net.Conn, cfg *config.Config, handler func(wire *SecureWire)) {
	sw, err := ServerHandshake(conn, cfg)
	if err != nil {
		return
	}
	handler(sw)
}

func ServerHandshake(conn net.Conn, cfg *config.Config) (wire *SecureWire, err error) {
	_, _, serr := challengeWithPuzzle(conn, cfg)
	if terminateHandshakeOnServerError(conn, serr, "challenging client with puzzle") {
		err = serr.err
		return
	}
	clientHello, serr := receiveAndVerifyClientHello(conn, cfg)
	if terminateHandshakeOnServerError(conn, serr, "reading and checking client ClientHello message") {
		err = serr.err
		return
	}
	cliShare, srvShare, serverKey, serr := negotiateSharedSecrets(conn, cfg, clientHello)
	if terminateHandshakeOnServerError(conn, serr, "negotiating shared secrets") {
		err = serr.err
		return
	}
	keySize := calculateSymmetricKeySize(clientHello, cfg)
	keysBytes := mixSharedSecretsForKey(srvShare, cliShare, keySize)
	wire, err = BuildSecureWire(keysBytes, conn, serverKey.IdAs32Byte(), clientHello.KeyId)
	if terminateHandshakeOnError(conn, err, "establishing secure wire") {
		return
	}
	//fmt.Println("Server session key (debug, disable in prod):", cryptoutil.EncB64(keysBytes))
	serr = handshakeOverSecureWire(wire)
	if terminateHandshakeOnServerError(conn, serr, "while handshaking over secure_wire") {
		err = serr.err
		return
	}
	return
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
	if clientHello.WireType != msg.WireTypeSimpleAES256 && clientHello.WireType != msg.WireTypeTripleAES256 && clientHello.WireType != msg.WireTypeTripleAES256Optional {
		return nil, Disconnect(
			errors.Errorf("wire type requested not supported: %v", clientHello.WireType),
			msg.DisconnectCauseProtocolRequestedNotSupported)
	}
	if cfg.TripleAES256 == config.TripleAES256Required && clientHello.WireType == msg.WireTypeSimpleAES256 {
		return nil, Disconnect(
			errors.Errorf("not enough security requested"),
			msg.DisconnectCauseNotEnoughSecurityRequested)
	}
	if cfg.TripleAES256 == config.TripleAES256Disabled && clientHello.WireType == msg.WireTypeTripleAES256 {
		return nil, Disconnect(
			errors.Errorf("too much security requested"),
			msg.DisconnectCauseTooMuchSecurityRequested)
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
	serverKey *config.Key,
	serr *ServerError) {

	symmetricKeySize := calculateSymmetricKeySize(clientHello, cfg)

	serverKey, err := cfg.GetKeyByCN(cfg.PreferredKeyCN)
	if err != nil {
		return clientShare, serverShare, serverKey,
			Disconnect(errors.Wrap(err, "serverKey specified by configuration not found"), msg.DisconnectCauseSeverMisconfiguration)
	}
	clientKey, err := cfg.GetKeyByID(clientHello.KeyIdAsString())
	if err != nil {
		// this should never happen has it has been verified by receiveAndVerifyClientHello()
		return clientShare, serverShare, serverKey,
			Disconnect(errors.Wrap(err, "clientKey specified not found"), msg.DisconnectCauseCounterpartyKeyIdNotRecognised)
	}
	serverPotp, err := cfg.GetPotpByCN(cfg.PreferredPotpCN)
	if err != nil {
		return clientShare, serverShare, serverKey,
			Disconnect(errors.Wrap(err, "serverPotp specified by configuration not found"), msg.DisconnectCauseSeverMisconfiguration)
	}

	wireType, serr := deriveWireType(clientHello.WireType, cfg.TripleAES256)
	if serr != nil {
		return
	}
	shrSecretReq := msg.SharedSecretRequest{
		RequestType: 0,
		KeyId:       serverKey.IdAs32Byte(),
		WireType:    wireType,
	}
	err = binary.Write(conn, binary.LittleEndian, shrSecretReq)
	if err != nil {
		return clientShare, serverShare, serverKey, Disconnect(err, msg.DisconnectCauseNone)
	}

	clientShare, serr = readSharedSecret(conn, serverKey, cfg, symmetricKeySize)
	if serr != nil {
		return
	}

	serverShare, serr = sendSharedSecret(conn, clientKey, serverPotp, symmetricKeySize)
	return
}

func deriveWireType(clientWireType msg.WireType, serverTripleAES256cfg config.TripleAES256Config) (wt msg.WireType, serr *ServerError) {
	if serverTripleAES256cfg == config.TripleAES256Allowed {
		if clientWireType == msg.WireTypeTripleAES256 || clientWireType == msg.WireTypeTripleAES256Optional {
			wt = msg.WireTypeTripleAES256
		} else {
			wt = msg.WireTypeSimpleAES256
		}
	} else if serverTripleAES256cfg == config.TripleAES256Required {
		if clientWireType == msg.WireTypeTripleAES256 || clientWireType == msg.WireTypeTripleAES256Optional {
			wt = msg.WireTypeTripleAES256
		} else {
			serr = Disconnect(errors.New("Not enough security"), msg.DisconnectCauseNotEnoughSecurityRequested)
		}
	} else if serverTripleAES256cfg == config.TripleAES256Disabled {
		if clientWireType == msg.WireTypeTripleAES256 {
			serr = Disconnect(errors.New("Client asking for too much security"), msg.DisconnectCauseTooMuchSecurityRequested)
		} else {
			wt = msg.WireTypeSimpleAES256
		}
	}
	return
}

func sendSharedSecret(conn net.Conn, receiver *config.Key, potp *config.Potp, symmetricKeySize int) (res *msg.SharedSecret, serr *ServerError) {
	potpBytes, potpOfs := potp.PickOTP(symmetricKeySize)
	secretsCount := calculateSharedSecretsCount(receiver.GetKeyType(), symmetricKeySize)
	//fmt.Printf("sent: otp ofs=%v len=%v val=%v\n", potpOfs, symmetricKeySize, base64.StdEncoding.EncodeToString(potpBytes))
	res = &msg.SharedSecret{
		Otp:    potpBytes,
		Shared: make([][]byte, secretsCount),
	}
	bundleDesc := msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   potp.IdAs32Byte(),
		PotpOffset:   potpOfs,
		SecretsCount: uint8(secretsCount),
		SecretSize:   uint16(cryptoutil.CipherTextSizeByKeyType[receiver.GetKeyType()].CipherText),
	}
	err := binary.Write(conn, binary.LittleEndian, &bundleDesc)
	if err != nil {
		return res, Disconnect(err, msg.DisconnectCauseNone)
	}

	for secretNo := 0; secretNo < secretsCount; secretNo++ {
		var ciphertext []byte
		ciphertext, res.Shared[secretNo], err = cryptoutil.Encapsulate(receiver.PubBytes(), receiver.GetKeyType())
		if err != nil {
			return res, Disconnect(err, msg.DisconnectCauseSeverMisconfiguration)
		}
		err = binary.Write(conn, binary.LittleEndian, ciphertext)
		if err != nil {
			return res, Disconnect(err, msg.DisconnectCauseNone)
		}
		//fmt.Printf("sent: secret[%v] %v (cipher: %v)\n", secretNo, cryptoutil.EncB64(res.Shared[secretNo]), cryptoutil.EncB64(ciphertext))
	}

	return res, nil
}

func readSharedSecret(conn net.Conn, receiver *config.Key, cfg *config.Config, symmetricKeySize int) (res *msg.SharedSecret, serr *ServerError) {
	bundleDesc := msg.SharedSecretBundleDescriptionResponse{}
	err := binary.Read(conn, binary.LittleEndian, &bundleDesc)
	if err != nil {
		return res, Disconnect(err, msg.DisconnectCauseNone)
	}

	cipherTextSize := cryptoutil.CipherTextSizeByKeyType[receiver.GetKeyType()].CipherText
	if int(bundleDesc.SecretSize) != cipherTextSize {
		return nil, Disconnect(
			errors.New(fmt.Sprintf("client secret-size not the expected to be provided=%v, expected=%v",
				bundleDesc.SecretSize, cipherTextSize)),
			msg.DisconnectCauseNotEnoughSecurityRequested)
	}

	if bundleDesc.SecretsCount == 0 || bundleDesc.SecretsCount > 10 {
		return nil, Disconnect(
			errors.New(fmt.Sprintf("client secret count out of range (0<n=<10), received: %v", bundleDesc.SecretsCount)),
			msg.DisconnectCauseNotEnoughSecurityRequested)
	}

	secretsCount := calculateSharedSecretsCount(receiver.GetKeyType(), symmetricKeySize)
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
	otpBytes, err := otp.ReadOTP(symmetricKeySize, bundleDesc.PotpOffset)
	if err != nil {
		return res, Disconnect(err, msg.DisconnectCauseSeverMisconfiguration)
	}
	//fmt.Printf("recv: otp ofs=%v size=%v val=%v\n", bundleDesc.PotpOffset, 32, base64.StdEncoding.EncodeToString(otpBytes))

	res = &msg.SharedSecret{
		Otp:    otpBytes,
		Shared: make([][]byte, bundleDesc.SecretsCount),
	}

	for count := 0; count < int(bundleDesc.SecretsCount); count++ {
		cipherText := make([]byte, bundleDesc.SecretSize)
		err = binary.Read(conn, binary.LittleEndian, cipherText)
		if err != nil {
			return res, Disconnect(err, msg.DisconnectCauseNone)
		}
		res.Shared[count], err =
			cryptoutil.Dencapsulate(receiver.PubBytes(), receiver.PvtBytes(), cipherText, receiver.GetKeyType())
		//fmt.Printf("recv: secret[%v] %v (cipher: %v)\n", count, cryptoutil.EncB64(res.Shared[count]), cryptoutil.EncB64(cipherText))
		if err != nil {
			return res, Disconnect(err, msg.DisconnectCauseNotEnoughSecurityRequested)
		}
	}
	return res, nil
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

func mixSharedSecretsForKey(serverShare *msg.SharedSecret, clientShare *msg.SharedSecret, keySize int) (key []byte) {
	allBytes := cryptoutil.ConcatAll(serverShare.SharesJoined(), clientShare.SharesJoined(), serverShare.Otp, clientShare.Otp)
	key = make([]byte, keySize)
	for i := 0; i < len(allBytes); i++ {
		key[i%keySize] = key[i%keySize] ^ allBytes[i]
	}
	return
}

func calculateSymmetricKeySize(clientHello *msg.ClientHello, serverConfig *config.Config) int {
	// at this stage, if the combination of server config/client hello can not be invalid i.e. server requires
	// TripleAES256 but client asks for SimpleAES256, client would have been disconnected during: receiveAndVerifyClientHello
	keySize := (256 / 8) + (96 / 8)

	if clientHello.WireType == msg.WireTypeTripleAES256 {
		keySize = keySize * 3
	} else if clientHello.WireType == msg.WireTypeTripleAES256Optional &&
		(serverConfig.TripleAES256 == config.TripleAES256Allowed || serverConfig.TripleAES256 == config.TripleAES256Required) {
		keySize = keySize * 3
	}
	return keySize
}

func calculateSharedSecretsCount(keyType cryptoutil.KeyType, symmetricKeySize int) int {
	sharedSecretSize := cryptoutil.CipherTextSizeByKeyType[keyType].SharedSecret
	secretsCount := symmetricKeySize / sharedSecretSize
	if (symmetricKeySize % sharedSecretSize) != 0 {
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
