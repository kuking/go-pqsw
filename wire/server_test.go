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
	"os"
	"testing"
)

//TODO: test for stale connections

var cfg *config.Config
var cPipe, sPipe net.Conn
var knockKnock msg.KnockKnock
var puzzleRequest msg.PuzzleRequest
var puzzleResponse msg.PuzzleResponse

func beforeEach() {
	cfg = config.NewEmpty()
	cPipe, sPipe = net.Pipe()
	go newClientHandshake(sPipe, cfg)
}

func teardown() {
	cPipe.Close()
	sPipe.Close()
	cfg = nil
}

func TestKnockKnock_EmptyPayload(t *testing.T) {
	knockKnock = msg.KnockKnock{
		KeyId:           [32]byte{},
		ProtocolVersion: 0,
		WireType:        0,
	}
	send(t, knockKnock)
	assertClosedConnection(t)
}

func TestKnockKnock_HappyPath(t *testing.T) {
	givenValidKnockKnock()
	send(t, knockKnock)
	recv(t, &puzzleRequest)
	assertConnectionStillOpen(t)
}

func testPuzzle_HappyPath(t *testing.T) {

	givenValidKnockKnock()
	send(t, knockKnock)
	recv(t, &puzzleRequest)
	puzzleResponse.Response = sha512lz.Solve(puzzleRequest.Body, int(puzzleRequest.Param))
	send(t, &puzzleResponse)

	//fmt.Printf("Client Received PuzzleRequest: %v", keyDerivationRequest)

}

func givenValidKnockKnock() {
	keyId, _ := cfg.CreateAndAddKey(config.KeyTypeSidhFp503) // first key, let's assume it is the server one
	keyId, _ = cfg.CreateAndAddKey(config.KeyTypeSidhFp503)  // second one, the client
	key, _ := cfg.GetKeyByID(*keyId)
	knockKnock = msg.KnockKnock{
		KeyId:           key.GetKeyIdAs32Byte(),
		ProtocolVersion: 1,
		WireType:        1,
	}
	fmt.Printf("TEST: Happy Valid KnockKnock with Key: %v\n", *keyId)
}

func assertClosedConnection(t *testing.T) {
	one := make([]byte, 1)
	if _, err := cPipe.Read(one); err != io.EOF {
		t.Fatal("Server should have disconnected.")
	}
}

func assertConnectionStillOpen(t *testing.T) {
	one := make([]byte, 1)
	if _, err := cPipe.Read(one); err == io.EOF {
		t.Fatal("Server should have not disconnected...")
	}
}

// --- common assertions ---

// --- utility methods ---
//
//func deriveKey(request *msg.PuzzleRequest) msg.PuzzleResponse {
//
//	if request.Puzzle != msg.PuzzleSHA512LZ {
//		panic("Sorry, I have only implemented SHA512LZ here")
//	}
//
//	res := msg.PuzzleResponse{
//		Response: [64]byte{},
//	}
//	const resSize = 32
//
//}

func printMessage(msg interface{}) {
	var buf bytes.Buffer
	binary.Write(io.Writer(&buf), binary.LittleEndian, msg)
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

func TestMain(m *testing.M) {
	beforeEach()
	defer teardown()
	os.Exit(m.Run())
}
