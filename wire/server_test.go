package wire

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
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
	assertClosedConnectionWithCause(t, msg.DisconnectCauseClientKeyNotRecognised)
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

func TestSharedSecretRequest_Happy(t *testing.T) {
	setup()
	defer cleanup()
	givenOtpInConfig()

	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)

	recv(t, &sharedSecretRequest)
	if sharedSecretRequest.RequestType != msg.SharedSecretRequestTypeKEMAndPotp {
		t.Error("sharedSecretRequest.RequestType should be 0, as so far the only version implemented")
	}

	serverKey, _ := cfg.GetKeyByID(sharedSecretRequest.KeyIdPreferredAsString())
	clientKey, _ := cfg.GetKeyByID(cfg.ClientKey)
	kem, _ := clientKey.GetKemSike()
	clientSecretsCount := 32 * 1 / kem.SharedSecretSize()
	if ((32 * 1) % kem.SharedSecretSize()) != 0 {
		clientSecretsCount += 1
	}

	potp, _ := cfg.GetPotpByID(sharedSecretRequest.PotpIdPreferredAsString())
	_, otpOffset := potp.PickOTP(32)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PubKeyIdUsed: clientKey.GetKeyIdAs32Byte(),
		PotpIdUsed:   potp.GetPotpIdAs32Byte(),
		PotpOffset:   otpOffset,
		SecretsCount: uint8(clientSecretsCount),
		SecretSize:   uint16(kem.CiphertextSize()),
	}
	send(t, sharedSecretBundleDescResponse)

	clientSecrets := make([][]byte, clientSecretsCount)
	for secretNo := 0; secretNo < clientSecretsCount; secretNo++ {
		clientSecrets[secretNo] = make([]byte, kem.SharedSecretSize())
		ciphertext := make([]byte, kem.CiphertextSize())
		err := kem.Encapsulate(ciphertext, clientSecrets[secretNo], serverKey.GetSidhPublicKey())
		if err != nil {
			panic(err)
		}
		send(t, ciphertext)
	}

	//recv(t, &sharedSecretBundleDescResponse)

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
	key, _ := cfg.GetKeyByID(cfg.ServerKey)
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

// ----------- common assertions -------------------------------------------------------------------------------------

func assertClosedConnectionWithCause(t *testing.T, reason uint32) {
	disconnectReason := msg.DisconnectCause{}
	recv(t, &disconnectReason)

	if disconnectReason.Delimiter != msg.DisconnectCauseDelimiter {
		t.Fatal("server did not send the right disconnect delimiter")
	}
	if disconnectReason.Cause != reason {
		t.Fatalf("expected disconnect cause %d, but got intead %d", reason, disconnectReason.Cause)
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
