package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
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
	go newClientHandshake(sPipe, cfg)
}

func cleanup() {
	_ = cPipe.Close()
	_ = sPipe.Close()
}

func TestConnect_DisconnectsASAP(t *testing.T) {
	setup()
	defer cleanup()
	_ = cPipe.Close()
	assertClosedConnection(t)
}

func TestConnect_DisconnectsAfterReceive(t *testing.T) {
	setup()
	defer cleanup()
	recv(t, &puzzleRequest)
	_ = cPipe.Close()
	assertClosedConnection(t)
}

func TestConnect_ServerUsesDifficultyFromConfig(t *testing.T) {
	logger.Init("test", true, false, os.Stdout)
	cfg = config.NewEmpty()
	cfg.PuzzleDifficulty = 12345
	cPipe, sPipe = net.Pipe()
	go newClientHandshake(sPipe, cfg)
	defer cleanup()

	recv(t, &puzzleRequest)
	if puzzleRequest.Param != 12345 {
		t.Fatal("server should use config entry 'PuzzleDifficulty'")
	}
}

func TestConnect_IncompletePuzzleAnswerAndCloses(t *testing.T) {
	setup()
	defer cleanup()
	recv(t, &puzzleRequest)
	send(t, []byte{1, 2, 3})
	_ = cPipe.Close()
	assertClosedConnection(t)
}

func TestConnect_Noise(t *testing.T) {
	setup()
	defer cleanup()
	recv(t, &puzzleRequest)
	if sendNoise(1<<20) < 20 {
		t.Error("this should have at least sent 20 bytes of noise before failing")
	}
	assertClosedConnectionWithCause(t, msg.DisconnectCausePuzzleNotSolved)
}

func TestConnect_WrongPuzzleAnswer(t *testing.T) {
	setup()
	defer cleanup()
	recv(t, &puzzleRequest)
	send(t, &msg.PuzzleResponse{}) //invalid response, should disconnect
	assertClosedConnectionWithCause(t, msg.DisconnectCausePuzzleNotSolved)
}

func TestConnect_HappyPuzzleAnswer(t *testing.T) {
	setup()
	defer cleanup()
	givenPuzzleAnswered(t)
	assertConnectionStillOpen(t)
}

func TestConnect_ClientClosesCorrectAnswer(t *testing.T) {
	setup()
	defer cleanup()
	givenPuzzleAnswered(t)
	_ = cPipe.Close()
	assertClosedConnection(t)
}

func TestClientHello_EmptyMessage(t *testing.T) {
	setup()
	defer cleanup()
	givenPuzzleAnswered(t)
	send(t, &msg.ClientHello{})
	assertClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestClientHello_Noise(t *testing.T) {
	setup()
	defer cleanup()
	givenPuzzleAnswered(t)
	if sendNoise(1<<20) < 20 {
		t.Error("this should have at least sent 20 bytes of noise before failing")
	}
	assertClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestClientHello_InvalidProtocolVersion(t *testing.T) {
	setup()
	defer cleanup()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	clientHello.Protocol = 1234
	send(t, clientHello)
	assertClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestClientHello_InvalidWireType(t *testing.T) {
	setup()
	defer cleanup()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	clientHello.WireType = 1234
	send(t, clientHello)
	assertClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestClientHello_WireType_TripleAES256(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	clientHello.WireType = msg.ClientHelloWireTypeTripleAES256
	send(t, clientHello)
	recv(t, &sharedSecretRequest)
	assertConnectionStillOpen(t)
}

func TestClientHello_ServerDisconnectsWhenTripleAES256Required(t *testing.T) {
	setup()
	defer cleanup()
	cfg.RequireTripleAES256 = true
	givenPuzzleAnswered(t)
	givenValidClientHello()
	send(t, clientHello)
	assertClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestClientHello_UnrecognizedKeyId(t *testing.T) {
	setup()
	defer cleanup()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	copy(clientHello.KeyId[5:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	send(t, clientHello)
	assertClosedConnectionWithCause(t, msg.DisconnectCauseCounterpartyKeyIdNotRecognised)
}

func TestClientHello_SendsAndDisconnects(t *testing.T) {
	setup()
	defer cleanup()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	send(t, clientHello)
	_ = cPipe.Close()
	assertClosedConnection(t)
}

func TestClientHello_HappyPath(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenValidClientHello()
	send(t, clientHello)
	recv(t, &sharedSecretRequest)
	assertConnectionStillOpen(t)
}

func TestSharedSecretRequest_Disconnect(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	recv(t, &sharedSecretRequest)
	_ = cPipe.Close()
	assertClosedConnection(t)
}

func TestSharedSecretRequest_EmptyResponse(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	givenSharedSecretRequestReceived(t)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{}
	send(t, sharedSecretBundleDescResponse)

	assertClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestSharedSecretRequest_InvalidSecretsCount(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	_, _, clientPotp := givenSharedSecretRequestReceived(t)

	send(t, msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.GetPotpIdAs32Byte(),
		PotpOffset:   123,
		SecretsCount: 0,
		SecretSize:   500,
	})
	assertClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestSharedSecretRequest_InvalidSecretSize(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	_, _, clientPotp := givenSharedSecretRequestReceived(t)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.GetPotpIdAs32Byte(),
		PotpOffset:   123,
		SecretsCount: 3,
		SecretSize:   1,
	}
	send(t, sharedSecretBundleDescResponse)
	assertClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestSharedSecretRequest_InvalidPotpId(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	givenSharedSecretRequestReceived(t)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   [32]byte{},
		PotpOffset:   123,
		SecretsCount: 3,
		SecretSize:   500,
	}
	send(t, sharedSecretBundleDescResponse)
	assertClosedConnectionWithCause(t, msg.DisconnectCausePotpNotRecognised)
}

func TestSharedSecretRequest_InsufficientSharedSecrets(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)

	_, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	_, kemsCount, kem := calculateKeySizeKemsCountAndKem(clientKey)
	send(t, msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.GetPotpIdAs32Byte(),
		PotpOffset:   123,
		SecretsCount: uint8(kemsCount + 1),
		SecretSize:   uint16(kem.CiphertextSize()),
	})

	assertClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestSharedSecretRequest_EmptyCiphertexts(t *testing.T) {
	setup()
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
	send(t, sharedSecretBundleDescResponse)

	for secretNo := 0; secretNo < clientSecretsCount; secretNo++ {
		ciphertext := make([]byte, kem.CiphertextSize())
		send(t, ciphertext)
	}

	recv(t, &sharedSecretBundleDescResponse) // implies the server is happy with the message
}

func TestShareSecretRequest_ClientSendsRandomSizeKem(t *testing.T) {
	//TODO
}

func TestShareSecretRequest_ClientSendsNoiseKemItShouldNotPanic(t *testing.T) {
	//TODO
}

func TestSharedSecretRequest_ClientSendsSharedSecretServerACK(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)

	givenClientSendsSharedSecret(t, clientKey, serverKey, clientPotp)
	recv(t, &sharedSecretBundleDescResponse) // implies the server is happy with the message
}

func TestSharedSecretRequest_ClientAndServerExchangeSharedSecret(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)

	givenClientSendsSharedSecret(t, clientKey, serverKey, clientPotp)

	recv(t, &sharedSecretBundleDescResponse) // implies the server is happy with the message
	ciphertext := make([]byte, sharedSecretBundleDescResponse.SecretSize)
	kem, _ := clientKey.GetKemSike()
	if kem.CiphertextSize() != len(ciphertext) {
		t.Error("secret size sent by server is wrong")
	}
	for i := 0; i < int(sharedSecretBundleDescResponse.SecretsCount); i++ {
		recv(t, ciphertext)
		err := kem.Decapsulate(ciphertext, clientKey.GetSidhPrivateKey(), serverKey.GetSidhPublicKey(), ciphertext)
		if err != nil {
			t.Error("kem failed to decapsulate", err)
		}
	}
	assertConnectionStillOpen(t)
}

func Test_SecureWireSetup(t *testing.T) {
	setup()
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

func Test_HappyPath(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()

	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	keySize, clientSecretsCount, kem := calculateKeySizeKemsCountAndKem(clientKey)
	clientPotpBytes, otpOffset := clientPotp.PickOTP(keySize)
	fmt.Printf("client sent: otp ofs=%v size=%v val=%v\n", otpOffset, keySize, base64.StdEncoding.EncodeToString(clientPotpBytes))

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.GetPotpIdAs32Byte(),
		PotpOffset:   otpOffset,
		SecretsCount: uint8(clientSecretsCount),
		SecretSize:   uint16(kem.CiphertextSize()),
	}
	send(t, sharedSecretBundleDescResponse)

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
		send(t, ciphertext)
		fmt.Printf("client sent: secret[%v] %v (cipher: %v)\n", secretNo, cryptoutil.EncB64(clientSecret.Shared[secretNo]), cryptoutil.EncB64(ciphertext))
	}

	recv(t, &sharedSecretBundleDescResponse)
	serverPotp, _ := cfg.GetPotpByID(sharedSecretBundleDescResponse.PotpIdAsString())
	serverPotpOfs := sharedSecretBundleDescResponse.PotpOffset
	serverPotpBytes, _ := serverPotp.ReadOTP(keySize, serverPotpOfs)
	fmt.Printf("client recv: otp ofs=%v len=%v val=%v\n", serverPotpOfs, keySize, cryptoutil.EncB64(serverPotpBytes))

	serverSecret := msg.SharedSecret{
		Otp:    serverPotpBytes,
		Shared: make([][]byte, sharedSecretBundleDescResponse.SecretsCount),
	}
	for secretNo := 0; secretNo < int(sharedSecretBundleDescResponse.SecretsCount); secretNo++ {
		ciphertext := make([]byte, sharedSecretBundleDescResponse.SecretSize)
		serverSecret.Shared[secretNo] = make([]byte, kem.SharedSecretSize())
		recv(t, &ciphertext)
		err := kem.Decapsulate(serverSecret.Shared[secretNo], clientKey.GetSidhPrivateKey(), clientKey.GetSidhPublicKey(), ciphertext)
		if err != nil {
			panic(err)
		}
		fmt.Printf("client recv: secret[%v] %v (cipher: %v)\n", secretNo, cryptoutil.EncB64(serverSecret.Shared[secretNo]), cryptoutil.EncB64(ciphertext))
	}

	keysBytes := mixSharedSecretsForKey(&serverSecret, &clientSecret, keySize)
	fmt.Printf("client' key: %v\n", cryptoutil.EncB64(keysBytes))

	sw, err := NewSecureWireAES256CGM(keysBytes[0:32], keysBytes[32:32+12], cPipe) // TODO: MISSING Triple AES256
	if err != nil {
		t.Errorf("could not stablish secure wire, err=%v", err)
	}
	gb := make([]byte, 4)
	n, err := sw.Read(gb)
	if n != 4 || err != nil {
		t.Error("error reading final secure_wire good confirmation")
	}
	if gb[0] != 'G' || gb[1] != 'O' || gb[2] != 'O' || gb[3] != 'D' {
		t.Error("the secure_write good confirmation is not correct")
	}
	// FIXME: This last one is not asserted by the server, as it closes connection ASAP
	n, err = sw.Write([]byte{'G', 'O', 'O', 'D'})
	if n != 4 || err != nil {
		t.Error("error writing final secure_wire good confirmation")
	}

	fmt.Println("Secure Connection was established successfully")
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
	recv(t, &puzzleRequest)
	puzzleResponse.Response = sha512lz.Solve(puzzleRequest.Body, int(puzzleRequest.Param))
	send(t, &puzzleResponse)
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
	send(t, clientHello)
}

func givenSharedSecretRequestReceived(t *testing.T) (serverKey *config.Key, clientKey *config.Key, clientPotp *config.Potp) {
	recv(t, &sharedSecretRequest)
	if sharedSecretRequest.RequestType != msg.SharedSecretRequestTypeKEMAndPotp {
		t.Error("sharedSecretRequest.RequestType should be 0, as so far the only version implemented")
	}
	serverKey, _ = cfg.GetKeyByID(sharedSecretRequest.KeyIdPreferredAsString())
	clientKey, _ = cfg.GetKeyByID(cfg.ClientKey)
	clientPotp, _ = cfg.GetPotpByID(cfg.ClientPotp)
	return serverKey, clientKey, clientPotp
}

func sendNoise(minimumAmount int) int {
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
			err = cPipe.SetWriteDeadline(time.Now().Add(time.Millisecond * 10))
		}
		if err == nil {
			err = binary.Write(cPipe, binary.LittleEndian, bunch)
		}
		count += len(bunch)
	}
	if err != nil {
		logger.Infof("SendNoise finished due to %v", err)
	}
	return count
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
	send(t, sharedSecretBundleDescResponse)

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
		send(t, ciphertext)
	}
	return &clientSecret
}

func givenServerSendsSharedSecret(t *testing.T, clientKey *config.Key, potp *config.Potp, keySize int) *msg.SharedSecret {
	recv(t, &sharedSecretBundleDescResponse)
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
		recv(t, ciphertext)
		sharedSecret.Shared[i] = make([]byte, kem.SharedSecretSize())
		err := kem.Decapsulate(sharedSecret.Shared[i], clientKey.GetSidhPrivateKey(), clientKey.GetSidhPublicKey(), ciphertext)
		if err != nil {
			t.Error("kem failed to decapsulate", err)
		}
	}
	return &sharedSecret
}

// ----------- common assertions -------------------------------------------------------------------------------------

func assertClosedConnectionWithCause(t *testing.T, reason uint32) {
	disconnectReason := msg.DisconnectCause{}
	recv(t, &disconnectReason)

	if disconnectReason.Delimiter != msg.DisconnectCauseDelimiter {
		t.Fatal("server did not send the right disconnect delimiter")
	}
	if disconnectReason.Cause != reason {
		t.Fatalf("expected disconnect cause: %v (%d), but got intead: %v (%d)",
			msg.DisconnectCauseString[reason], reason,
			msg.DisconnectCauseString[disconnectReason.Cause], disconnectReason.Cause)
	}
	assertClosedConnection(t)
}

func assertClosedConnection(t *testing.T) {
	one := make([]byte, 1)
	if c, err := cPipe.Read(one); err == nil {
		t.Fatalf("client pipe should have disconnected. But read count: %v", c)
	}
	if c, err := sPipe.Read(one); err == nil {
		t.Fatalf("server pipe should have disconnected. But read count: %v", c)
	}
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

func send(t *testing.T, msg interface{}) {
	err := binary.Write(cPipe, binary.LittleEndian, msg)
	if err != nil {
		t.Errorf("Client->Server failed to send '%v' with: %v", msg, err)
	}
}

func recv(t *testing.T, msg interface{}) {
	err := binary.Read(cPipe, binary.LittleEndian, msg)
	if err != nil {
		t.Errorf("Client failed to receive: %v", err)
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
