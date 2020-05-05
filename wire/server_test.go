package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"io"
	"net"
	"testing"
	"time"
)

//TODO: test for stale connections

var cfg *config.Config
var cPipe, sPipe net.Conn

var knockKnock msg.KnockKnock
var puzzleRequest msg.PuzzleRequest
var puzzleResponse msg.PuzzleResponse
var sharedSecretRequest msg.SharedSecretRequest

func setup() {
	cfg = config.NewEmpty()
	cPipe, sPipe = net.Pipe()
	go newClientHandshake(sPipe, cfg)
}

func cleanup() {
	_ = cPipe.Close()
	_ = sPipe.Close()
}

func TestKnockKnock_EmptyPayload(t *testing.T) {
	setup()
	defer cleanup()
	knockKnock = msg.KnockKnock{
		KeyId:           [32]byte{},
		ProtocolVersion: 0,
		WireType:        0,
	}
	send(t, knockKnock)
	assertClosedConnection(t)
}

func TestKnockKnock_ClosesWithoutSending(t *testing.T) {
	setup()
	defer cleanup()

	_ = cPipe.Close()

	assertClosedConnection(t)
}

func TestKnockKnock_ClosesIncompleteSend(t *testing.T) {
	setup()
	defer cleanup()

	send(t, []byte{1, 2, 3})
	_ = cPipe.Close()

	assertClosedConnection(t)
}

func TestKnockKnock_Spam(t *testing.T) {
	setup()
	defer cleanup()

	var err error
	for i := 0; i < 1000 && err == nil; i++ {
		err = binary.Write(cPipe, binary.LittleEndian, []byte{1, 2, 3, 4, 5})
	}
	assertClosedConnection(t)
}

func TestKnockKnock_InvalidProtocolVersion(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	knockKnock.ProtocolVersion = 1234
	send(t, knockKnock)
	assertClosedConnection(t)
}

func TestKnockKnock_InvalidWireType(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	knockKnock.WireType = 1234
	send(t, knockKnock)
	assertClosedConnection(t)
}

func TestKnockKnock_WireType_TripleAES256(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	knockKnock.WireType = msg.WireType_TripleAES256
	send(t, knockKnock)
	recv(t, &puzzleRequest)
	assertConnectionStillOpen(t)
}

func TestKnockKnock_UnrecognizedKeyId(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	copy(knockKnock.KeyId[5:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	send(t, knockKnock)
	assertClosedConnection(t)
}

func TestKnockKnock_HappyPath(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knockKnock)
	recv(t, &puzzleRequest)
	assertConnectionStillOpen(t)
}

func TestPuzzleResponse_DisconnectOnRequest(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knockKnock)
	recv(t, &puzzleRequest)
	_ = cPipe.Close()

	assertClosedConnection(t)
}

func TestPuzzleResponse_HalfAnswerAndDisconnect(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knockKnock)
	recv(t, &puzzleRequest)
	send(t, []byte{1, 2, 3})
	_ = cPipe.Close()

	assertClosedConnection(t)
}

func TestPuzzleResponse_InvalidResponse(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knockKnock)
	recv(t, &puzzleRequest)
	send(t, &msg.PuzzleResponse{}) //invalid response, should disconnect

	assertClosedConnection(t)
}

func TestPuzzleResponse_SpamResponse(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knockKnock)
	recv(t, &puzzleRequest)
	var err error
	for i := 0; i < 1000 && err == nil; i++ {
		err = binary.Write(cPipe, binary.LittleEndian, []byte{1, 2, 3, 4, 5})
	}
	assertClosedConnection(t)
}

func TestPuzzle_HappyPath(t *testing.T) {
	setup()
	defer cleanup()

	givenValidKnockKnock()
	send(t, knockKnock)
	recv(t, &puzzleRequest)
	puzzleResponse.Response = sha512lz.Solve(puzzleRequest.Body, int(puzzleRequest.Param))
	send(t, &puzzleResponse)
	recv(t, &sharedSecretRequest)
	//fmt.Print("SharedSecretRequest", sharedSecretRequest)
	assertConnectionStillOpen(t)

}

func givenValidKnockKnock() {
	keyId, _ := cfg.CreateAndAddKey(config.KeyTypeSidhFp503) // first key, let's assume it is the server one
	keyId, _ = cfg.CreateAndAddKey(config.KeyTypeSidhFp503)  // second one, the client
	key, _ := cfg.GetKeyByID(*keyId)
	knockKnock = msg.KnockKnock{
		KeyId:           key.GetKeyIdAs32Byte(),
		ProtocolVersion: msg.ProtocolVersion,
		WireType:        msg.WireType_SimpleAES256,
	}
	fmt.Printf("TEST: Happy Valid KnockKnock with Key: %v\n", *keyId)
}

// ----------- common assertions -------------------------------------------------------------------------------------

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

func printMessage(msg interface{}) {
	var buf bytes.Buffer
	_ = binary.Write(io.Writer(&buf), binary.LittleEndian, msg)
	fmt.Printf("Msg: %v \nLen: %d \nHex: %v\n", buf.Bytes(), len(buf.Bytes()), hex.EncodeToString(buf.Bytes()))
}

func send(t *testing.T, msg interface{}) {
	err := binary.Write(cPipe, binary.LittleEndian, msg)
	if err != nil {
		t.Errorf("Client->Server failed to send '%v' with: %v", msg, err)
	}
}

func recv(t *testing.T, msg interface{}) {
	err := binary.Read(cPipe, binary.LittleEndian, msg)
	if err != nil {
		t.Errorf("Client->Server failed to send with: %v", err)
	}
}
