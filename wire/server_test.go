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

var knock msg.Knock
var puzzleRequest msg.PuzzleRequest
var puzzleResponse msg.PuzzleResponse
var sharedSecretRequest msg.SharedSecretRequest

func setup() {
	logger.Init("test", true, false, os.Stdout)
	cfg = config.NewEmpty()
	cPipe, sPipe = net.Pipe()
	go newClientHandshake(sPipe, cfg)
}

func cleanup() {
	_ = cPipe.Close()
	_ = sPipe.Close()
}

func TestKnock_EmptyPayload(t *testing.T) {
	setup()
	defer cleanup()
	send(t, msg.Knock{})
	assertClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestKnock_ClientClosesASAP(t *testing.T) {
	setup()
	defer cleanup()
	_ = cPipe.Close()
	assertClosedConnection(t)
}

func TestKnock_ClosesIncompleteSend(t *testing.T) {
	setup()
	defer cleanup()
	send(t, []byte{1, 2, 3})
	_ = cPipe.Close()
	assertClosedConnection(t)
}

func TestKnock_Noise(t *testing.T) {
	setup()
	defer cleanup()

	if sendNoise(1<<20) < 20 {
		t.Error("This should have at least sent 20 bytes of noise before failing")
	}

	assertClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestKnock_InvalidProtocolVersion(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	knock.ProtocolVersion = 1234
	send(t, knock)
	assertClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestKnock_InvalidWireType(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	knock.WireType = 1234
	send(t, knock)

	assertClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestKnock_WireType_TripleAES256(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	knock.WireType = msg.WireTypeTripleAES256
	send(t, knock)
	recv(t, &puzzleRequest)
	assertConnectionStillOpen(t)
}

func TestKnock_UnrecognizedKeyId(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	copy(knock.KeyId[5:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	send(t, knock)
	assertClosedConnectionWithCause(t, msg.DisconnectCauseClientKeyNotRecognised)
}

func TestKnock_GoodButDisconnects(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knock)
	_ = cPipe.Close()

	assertClosedConnection(t)
}

func TestKnock_ServerKicksOutWhenTripleAES256Required(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	cfg.RequireTripleAES256 = true

	send(t, knock)
	assertClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestKnock_HappyPath(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knock)
	recv(t, &puzzleRequest)
	assertConnectionStillOpen(t)
}

func TestPuzzleResponse_DisconnectOnRequest(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knock)
	recv(t, &puzzleRequest)
	_ = cPipe.Close()

	assertClosedConnection(t)
}

func TestPuzzleResponse_HalfAnswerAndDisconnect(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knock)
	recv(t, &puzzleRequest)
	send(t, []byte{1, 2, 3})
	_ = cPipe.Close()

	assertClosedConnection(t)
}

func TestPuzzleResponse_InvalidResponse(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knock)
	recv(t, &puzzleRequest)
	send(t, &msg.PuzzleResponse{}) //invalid response, should disconnect

	assertClosedConnectionWithCause(t, msg.DisconnectCausePuzzleNotSolved)
}

func TestPuzzleResponse_NoiseResponse(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knock)
	recv(t, &puzzleRequest)
	if sendNoise(1<<20) < 20 {
		t.Error("This should have at least sent 20 bytes of noise before failing")
	}

	assertClosedConnectionWithCause(t, msg.DisconnectCausePuzzleNotSolved)
}

func TestPuzzleResponse_GoodButDisconnects(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knock)
	recv(t, &puzzleRequest)
	puzzleResponse.Response = sha512lz.Solve(puzzleRequest.Body, int(puzzleRequest.Param))
	send(t, &puzzleResponse)
	_ = cPipe.Close()

	assertClosedConnection(t)
}

func TestPuzzleResponse_ServerUsesDifficultyFromConfig(t *testing.T) {
	setup()
	defer cleanup()

	cfg.PuzzleDifficulty = 12345
	givenValidKnockKnock()
	send(t, knock)
	recv(t, &puzzleRequest)
	if puzzleRequest.Param != 12345 {
		t.Fatal("server should use config entry 'PuzzleDifficulty'")
	}
}

func TestPuzzle_HappyPath(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knock)
	recv(t, &puzzleRequest)
	puzzleResponse.Response = sha512lz.Solve(puzzleRequest.Body, int(puzzleRequest.Param))
	send(t, &puzzleResponse)
	recv(t, &sharedSecretRequest)
	//fmt.Print("SharedSecretRequest", sharedSecretRequest)
	assertConnectionStillOpen(t)

}

func givenServerAndClientKeys() {
	keyId, _ := cfg.CreateAndAddKey(cryptoutil.KeyTypeSidhFp503) // first key, let's assume it is the server one
	cfg.ServerKey = *keyId
	keyId, _ = cfg.CreateAndAddKey(cryptoutil.KeyTypeSidhFp503) // second one, the client
}

func givenValidKnockKnock() {
	givenServerAndClientKeys()
	key, _ := cfg.GetKeyByID(cfg.ServerKey)
	knock = msg.Knock{
		KeyId:           key.GetKeyIdAs32Byte(),
		ProtocolVersion: msg.ProtocolVersion,
		WireType:        msg.WireTypeSimpleAES256,
	}
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
		t.Fatalf("Server should have disconnected. But read count: %v", c)
	}
}

func assertConnectionStillOpen(t *testing.T) {
	one := make([]byte, 1)
	_ = cPipe.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
	if _, err := cPipe.Read(one); err == io.EOF {
		t.Fatal("Server should have not disconnected...")
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
