package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/google/logger"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

//TODO: test for stale connections

var cfg *config.Config
var cPipe, sPipe net.Conn

var clientHello msg.ClientHello
var puzzleRequest msg.PuzzleRequest
var puzzleResponse msg.PuzzleResponse
var sharedSecretRequest msg.SharedSecretRequest
var sharedSecretBundleDescResponse msg.SharedSecretBundleDescriptionResponse

func setup() {
	logger.Init("test", true, false, os.Stdout)
	cfg = config.NewEmpty()
	cfg.PuzzleDifficulty = 10 // smaller value increases false positives in 'random/noise answer to the puzzle' tests
	// 10 is pretty fast, no need to be specific about those tests at this time.
	cPipe, sPipe = net.Pipe()
}

func serverSetup() {
	setup()
	go newClientHandshake(sPipe, cfg)
}

func cleanup() {
	_ = cPipe.Close()
	_ = sPipe.Close()
}

func TestServerConnect_DisconnectsASAP(t *testing.T) {
	serverSetup()
	defer cleanup()
	_ = cPipe.Close()
	assertServerClosedConnection(t)
}

func TestServerConnect_DisconnectsAfterReceive(t *testing.T) {
	serverSetup()
	defer cleanup()
	cRecv(t, &puzzleRequest)
	_ = cPipe.Close()
	assertServerClosedConnection(t)
}

func TestServerConnect_ServerUsesDifficultyFromConfig(t *testing.T) {
	logger.Init("test", true, false, os.Stdout)
	cfg = config.NewEmpty()
	cfg.PuzzleDifficulty = 12345
	cPipe, sPipe = net.Pipe()
	go newClientHandshake(sPipe, cfg)
	defer cleanup()

	cRecv(t, &puzzleRequest)
	if puzzleRequest.Param != 12345 {
		t.Fatal("server should use config entry 'PuzzleDifficulty'")
	}
}

func TestServerConnect_IncompletePuzzleAnswerAndCloses(t *testing.T) {
	serverSetup()
	defer cleanup()
	cRecv(t, &puzzleRequest)
	cSend(t, []byte{1, 2, 3})
	_ = cPipe.Close()
	assertServerClosedConnection(t)
}

func TestServerConnect_Noise(t *testing.T) {
	serverSetup()
	defer cleanup()
	cRecv(t, &puzzleRequest)
	if ClientSendsNoise(1<<20) < 20 {
		t.Error("this should have at least sent 20 bytes of noise before failing")
	}
	assertServerClosedConnectionWithCause(t, msg.DisconnectCausePuzzleNotSolved)
}

func TestServerConnect_WrongPuzzleAnswer(t *testing.T) {
	serverSetup()
	defer cleanup()
	cRecv(t, &puzzleRequest)
	cSend(t, &msg.PuzzleResponse{}) //invalid response, should disconnect
	assertServerClosedConnectionWithCause(t, msg.DisconnectCausePuzzleNotSolved)
}

func TestServerConnect_HappyPuzzleAnswer(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenPuzzleAnswered(t)
	assertConnectionStillOpen(t)
}

func TestServerConnect_ClientClosesCorrectAnswer(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenPuzzleAnswered(t)
	_ = cPipe.Close()
	assertServerClosedConnection(t)
}

func TestServerClientHello_EmptyMessage(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenPuzzleAnswered(t)
	cSend(t, &msg.ClientHello{})
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestServerClientHello_Noise(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenPuzzleAnswered(t)
	if ClientSendsNoise(1<<20) < 20 {
		t.Error("this should have at least sent 20 bytes of noise before failing")
	}
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestServerClientHello_InvalidProtocolVersion(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	clientHello.Protocol = 1234
	cSend(t, clientHello)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestServerClientHello_InvalidWireType(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	clientHello.WireType = 1234
	cSend(t, clientHello)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestServerClientHello_WireType_TripleAES256(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	clientHello.WireType = msg.ClientHelloWireTypeTripleAES256
	cSend(t, clientHello)
	cRecv(t, &sharedSecretRequest)
	assertConnectionStillOpen(t)
}

func TestServerClientHello_ServerDisconnectsWhenTripleAES256Required(t *testing.T) {
	serverSetup()
	defer cleanup()
	cfg.RequireTripleAES256 = true
	givenPuzzleAnswered(t)
	givenValidClientHello()
	cSend(t, clientHello)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerClientHello_UnrecognizedKeyId(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	copy(clientHello.KeyId[5:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	cSend(t, clientHello)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseCounterpartyKeyIdNotRecognised)
}

func TestServerClientHello_SendsAndDisconnects(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	cSend(t, clientHello)
	_ = cPipe.Close()
	assertServerClosedConnection(t)
}

func TestServerClientHello_HappyPath(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	cSend(t, clientHello)
	cRecv(t, &sharedSecretRequest)
	assertConnectionStillOpen(t)
}

func TestServerSharedSecretRequest_Disconnect(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	cRecv(t, &sharedSecretRequest)
	_ = cPipe.Close()
	assertServerClosedConnection(t)
}

func TestServerSharedSecretRequest_EmptyResponse(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	givenSharedSecretRequestReceived(t)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{}
	cSend(t, sharedSecretBundleDescResponse)

	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerSharedSecretRequest_InvalidSecretsCount(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	_, _, clientPotp := givenSharedSecretRequestReceived(t)

	cSend(t, msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.GetPotpIdAs32Byte(),
		PotpOffset:   123,
		SecretsCount: 0,
		SecretSize:   500,
	})
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerSharedSecretRequest_InvalidPotpId(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	givenSharedSecretRequestReceived(t)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   [32]byte{},
		PotpOffset:   123,
		SecretsCount: 3,
		SecretSize:   402,
	}
	cSend(t, sharedSecretBundleDescResponse)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCausePotpNotRecognised)
}

func TestServerSharedSecretRequest_InsufficientSharedSecrets(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)

	_, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	_, kemsCount, kem := calculateKeySizeKemsCountAndKem(clientKey)
	cSend(t, msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.GetPotpIdAs32Byte(),
		PotpOffset:   123,
		SecretsCount: uint8(kemsCount + 1),
		SecretSize:   uint16(kem.CiphertextSize()),
	})

	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerSharedSecretRequest_EmptyCiphertexts(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()

	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	_, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	_, clientSecretsCount, kem := calculateKeySizeKemsCountAndKem(clientKey)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.GetPotpIdAs32Byte(),
		PotpOffset:   0,
		SecretsCount: uint8(clientSecretsCount),
		SecretSize:   uint16(kem.CiphertextSize()),
	}
	cSend(t, sharedSecretBundleDescResponse)

	for secretNo := 0; secretNo < clientSecretsCount; secretNo++ {
		ciphertext := make([]byte, kem.CiphertextSize())
		cSend(t, ciphertext)
	}

	cRecv(t, &sharedSecretBundleDescResponse) // implies the server is happy with the message
}

func TestServerShareSecretRequest_ClientSendsInvalidSizeKem(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()

	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	_, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	_, clientSecretsCount, kem := calculateKeySizeKemsCountAndKem(clientKey)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.GetPotpIdAs32Byte(),
		PotpOffset:   0,
		SecretsCount: uint8(clientSecretsCount),
		SecretSize:   uint16(kem.CiphertextSize() + 25),
	}

	cSend(t, sharedSecretBundleDescResponse)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerShareSecretRequest_ClientSendsNoiseKemItShouldNotPanic(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()

	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	givenSharedSecretRequestReceived(t)
	ClientSendsNoise(10000)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerSharedSecretRequest_ClientSendsSharedSecretServerACK(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)

	givenClientSendsSharedSecret(t, clientKey, serverKey, clientPotp)
	cRecv(t, &sharedSecretBundleDescResponse) // implies the server is happy with the message
}

func TestServerSharedSecretRequest_ClientAndServerExchangeSharedSecret(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)

	givenClientSendsSharedSecret(t, clientKey, serverKey, clientPotp)

	cRecv(t, &sharedSecretBundleDescResponse) // implies the server is happy with the message
	ciphertext := make([]byte, sharedSecretBundleDescResponse.SecretSize)
	kem, _ := clientKey.GetKemSike()
	if kem.CiphertextSize() != len(ciphertext) {
		t.Error("secret size sent by server is wrong")
	}
	for i := 0; i < int(sharedSecretBundleDescResponse.SecretsCount); i++ {
		cRecv(t, ciphertext)
		err := kem.Decapsulate(ciphertext, clientKey.GetSidhPrivateKey(), serverKey.GetSidhPublicKey(), ciphertext)
		if err != nil {
			t.Error("kem failed to decapsulate", err)
		}
	}
	assertConnectionStillOpen(t)
}

func TestServer_SecureWireSetup(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)

	clientShare := givenClientSendsSharedSecret(t, clientKey, serverKey, clientPotp)
	keySize := len(clientShare.Otp) // otp size will be the same as keySize, .. so far
	serverShare := givenServerSendsSharedSecret(t, clientKey, clientPotp, keySize)

	sharedKey := mixSharedSecretsForKey(serverShare, clientShare, keySize) // FIXME: method is not being tested ...
	_, err := NewSecureWireAES256CGM(sharedKey[0:32], sharedKey[32:32+12], cPipe)
	if err != nil {
		t.Errorf("could not establish secure_wire, error=%v", err)
	}
}

func TestServer_SecureWriteGoodMessageInvalid(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	clientShare := givenClientSendsSharedSecret(t, clientKey, serverKey, clientPotp)
	keySize := len(clientShare.Otp) // otp size will be the same as keySize, .. so far
	serverShare := givenServerSendsSharedSecret(t, clientKey, clientPotp, keySize)
	sharedKey := mixSharedSecretsForKey(serverShare, clientShare, keySize)
	sw, err := NewSecureWireAES256CGM(sharedKey[0:32], sharedKey[32:32+12], cPipe)
	if err != nil {
		t.Error(err)
	}
	gb := make([]byte, 4)
	n, err := sw.Read(gb)
	if n != 4 || err != nil || !bytes.Equal(gb[:], []byte{'G', 'O', 'O', 'D'}) {
		t.Error("error reading final secure_wire good confirmation")
	}
	_, _ = sw.Write([]byte{'N', 'O', 'G', 'O', 'O', 'D'})
	assertServerClosedConnection(t)
}

func TestServer_HappyPath(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	clientShare := givenClientSendsSharedSecret(t, clientKey, serverKey, clientPotp)
	keySize := len(clientShare.Otp) // otp size will be the same as keySize, .. so far
	serverShare := givenServerSendsSharedSecret(t, clientKey, clientPotp, keySize)
	sharedKey := mixSharedSecretsForKey(serverShare, clientShare, keySize)
	sw, err := NewSecureWireAES256CGM(sharedKey[0:32], sharedKey[32:32+12], cPipe)
	if err != nil {
		t.Error(err)
	}
	gb := make([]byte, 4)
	n, err := sw.Read(gb)
	if n != 4 || err != nil || !bytes.Equal(gb[:], []byte{'G', 'O', 'O', 'D'}) {
		t.Error("error reading final secure_wire good confirmation")
	}
	_, _ = sw.Write([]byte{'G', 'O', 'O', 'D'})
	assertConnectionStillOpen(t)
}

// ----- givens ------------------------------------------------------------------------------------------------------

func givenServerAndClientKeys() {
	key, _ := cfg.CreateAndAddKey(cryptoutil.KeyTypeSidhFp503) // first key, let's assume it is the server one
	cfg.ServerKey = key.Uuid
	key, _ = cfg.CreateAndAddKey(cryptoutil.KeyTypeSidhFp503) // second one, the client
	cfg.ClientKey = key.Uuid
}

func givenOtpInConfig() {
	potp, _ := cfg.CreateInPlacePotp(4096)
	cfg.ServerPotp = potp.Uuid
	cfg.ClientPotp = potp.Uuid
}

func givenPuzzleAnswered(t *testing.T) {
	cRecv(t, &puzzleRequest)
	puzzleResponse.Response = sha512lz.Solve(puzzleRequest.Body, int(puzzleRequest.Param))
	cSend(t, &puzzleResponse)
}

func givenValidClientHello() {
	givenServerAndClientKeys()
	key, _ := cfg.GetKeyByID(cfg.ClientKey)
	clientHello = msg.ClientHello{
		KeyId:    key.GetKeyIdAs32Byte(),
		Protocol: msg.ClientHelloProtocol,
		WireType: msg.ClientHelloWireTypeSimpleAES256,
	}
}

func givenClientHelloAnswered(t *testing.T) {
	givenValidClientHello()
	cSend(t, clientHello)
}

func givenSharedSecretRequestReceived(t *testing.T) (serverKey *config.Key, clientKey *config.Key, clientPotp *config.Potp) {
	cRecv(t, &sharedSecretRequest)
	if sharedSecretRequest.RequestType != msg.SharedSecretRequestTypeKEMAndPotp {
		t.Error("sharedSecretRequest.RequestType should be 0, as so far the only version implemented")
	}
	serverKey, _ = cfg.GetKeyByID(sharedSecretRequest.KeyIdPreferredAsString())
	if serverKey.Uuid != cfg.ServerKey {
		t.Error("server sent another key")
	}
	clientKey, _ = cfg.GetKeyByID(cfg.ClientKey)
	clientPotp, _ = cfg.GetPotpByID(cfg.ClientPotp)
	return serverKey, clientKey, clientPotp
}

func sendNoise(conn net.Conn, minimumAmount int) int {
	// it sends multiples of 32 bytes, no need to be precise with this
	var bunch [32]byte
	var err error
	count := 0
	for count < minimumAmount && err == nil {
		var n int
		n, err = rand.Read(bunch[:])
		if n != len(bunch) {
			err = errors.New("problem creating randomness")
		}
		if err == nil {
			err = conn.SetWriteDeadline(time.Now().Add(time.Millisecond * 10))
		}
		if err == nil {
			err = binary.Write(conn, binary.LittleEndian, bunch)
		}
		count += len(bunch)
	}
	if err != nil {
		logger.Infof("SendNoise finished due to %v", err)
	}
	return count
}

func ClientSendsNoise(minimumAmount int) int {
	return sendNoise(cPipe, minimumAmount)
}

func ServerSendsNoise(minimumAmount int) int {
	return sendNoise(cPipe, minimumAmount)
}

func givenClientSendsSharedSecret(t *testing.T, clientKey *config.Key, serverKey *config.Key, clientPotp *config.Potp) *msg.SharedSecret {
	keySize, clientSecretsCount, kem := calculateKeySizeKemsCountAndKem(clientKey)
	clientPotpBytes, otpOffset := clientPotp.PickOTP(keySize)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.GetPotpIdAs32Byte(),
		PotpOffset:   otpOffset,
		SecretsCount: uint8(clientSecretsCount),
		SecretSize:   uint16(kem.CiphertextSize()),
	}
	cSend(t, sharedSecretBundleDescResponse)

	clientSecret := msg.SharedSecret{
		Otp:    clientPotpBytes,
		Shared: make([][]byte, clientSecretsCount),
	}
	for secretNo := 0; secretNo < clientSecretsCount; secretNo++ {
		clientSecret.Shared[secretNo] = make([]byte, kem.SharedSecretSize())
		ciphertext := make([]byte, kem.CiphertextSize())
		err := kem.Encapsulate(ciphertext, clientSecret.Shared[secretNo], serverKey.GetSidhPublicKey())
		if err != nil {
			panic(err)
		}
		cSend(t, ciphertext)
	}
	return &clientSecret
}

func givenServerSendsSharedSecret(t *testing.T, clientKey *config.Key, potp *config.Potp, keySize int) *msg.SharedSecret {
	cRecv(t, &sharedSecretBundleDescResponse)
	clientPotpId := potp.GetPotpIdAs32Byte()
	if !bytes.Equal(sharedSecretBundleDescResponse.PotpIdUsed[:], clientPotpId[:]) {
		t.Error("Server is asking to use another potp ... which MIGHT be fine, but it is not implemented so far, it should not")
	}
	potpBytes, err := potp.ReadOTP(keySize, sharedSecretBundleDescResponse.PotpOffset)
	if err != nil {
		t.Errorf("Failed to retrieve potp bytes, err=%v", err)
	}
	sharedSecret := msg.SharedSecret{
		Otp:    potpBytes,
		Shared: make([][]byte, sharedSecretBundleDescResponse.SecretsCount),
	}

	ciphertext := make([]byte, sharedSecretBundleDescResponse.SecretSize)
	kem, _ := clientKey.GetKemSike()
	if kem.CiphertextSize() != len(ciphertext) {
		t.Error("secret size sent by server is wrong")
	}
	for i := 0; i < int(sharedSecretBundleDescResponse.SecretsCount); i++ {
		cRecv(t, ciphertext)
		sharedSecret.Shared[i] = make([]byte, kem.SharedSecretSize())
		err := kem.Decapsulate(sharedSecret.Shared[i], clientKey.GetSidhPrivateKey(), clientKey.GetSidhPublicKey(), ciphertext)
		if err != nil {
			t.Error("kem failed to decapsulate", err)
		}
	}
	return &sharedSecret
}

// ----------- common assertions -------------------------------------------------------------------------------------

func assertServerClosedConnectionWithCause(t *testing.T, reason uint32) {
	disconnectReason := msg.DisconnectCause{}
	cRecv(t, &disconnectReason)

	if disconnectReason.Delimiter != msg.DisconnectCauseDelimiter {
		t.Fatal("server did not send the right disconnect delimiter")
	}
	if disconnectReason.Cause != reason {
		t.Fatalf("expected disconnect cause: %v (%d), but got intead: %v (%d)",
			msg.DisconnectCauseString[reason], reason,
			msg.DisconnectCauseString[disconnectReason.Cause], disconnectReason.Cause)
	}
	assertServerClosedConnection(t)
}

func assertClosedConnection(conn net.Conn, t *testing.T) {
	one := make([]byte, 1)
	if c, err := conn.Read(one); err == nil {
		t.Fatalf("pipe should have disconnected. But read count: %v", c)
	}
	if c, err := conn.Read(one); err == nil {
		t.Fatalf("pipe should have disconnected. But read count: %v", c)
	}
}

func assertServerClosedConnection(t *testing.T) {
	assertClosedConnection(cPipe, t)
}

func assertClientClosedConnection(t *testing.T) {
	assertClosedConnection(sPipe, t)
}

func assertConnectionStillOpen(t *testing.T) {
	one := make([]byte, 1)
	_ = cPipe.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	if _, err := cPipe.Read(one); err == io.EOF {
		t.Fatal("client pipe should have not disconnected...")
	}
	_ = sPipe.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	if _, err := sPipe.Read(one); err == io.EOF {
		t.Fatal("server pipe should have not disconnected...")
	}
}

// ----------- misc --------------------------------------------------------------------------------------------------

func cSend(t *testing.T, msg interface{}) {
	err := binary.Write(cPipe, binary.LittleEndian, msg)
	if err != nil {
		t.Errorf("Client->Server failed to send '%v' with: %v", msg, err)
	}
}

func cRecv(t *testing.T, msg interface{}) {
	err := binary.Read(cPipe, binary.LittleEndian, msg)
	if err != nil {
		t.Errorf("Client failed to receive: %v", err)
	}
}

func sSend(t *testing.T, msg interface{}) {
	err := binary.Write(sPipe, binary.LittleEndian, msg)
	if err != nil {
		t.Errorf("Server->Client failed to send '%v' with: %v", msg, err)
	}
}

func sRecv(t *testing.T, msg interface{}) {
	err := binary.Read(sPipe, binary.LittleEndian, msg)
	if err != nil {
		t.Errorf("Server failed to receive: %v", err)
	}
}

func calculateKeySizeKemsCountAndKem(clientKey *config.Key) (keySize int, secretsCount int, kem *sidh.KEM) {
	keySize = (256 / 8) + (96 / 8)
	if clientHello.WireType == msg.ClientHelloWireTypeTripleAES256 {
		keySize = keySize * 3
	}
	kem, _ = clientKey.GetKemSike()
	secretsCount = keySize / kem.SharedSecretSize()
	if (keySize % kem.SharedSecretSize()) != 0 {
		secretsCount += 1
	}
	return keySize, secretsCount, kem
}
