package wire

import (
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"testing"
)

// most of common asserts, givens, etc. in server_test.go
func clientSetup() {
	setup()
	givenServerAndClientKeys()
	go NewServerHandshake(cPipe, cfg)
}

func TestClient_ConnectWithNoise(t *testing.T) {
	clientSetup()
	defer cleanup()

	ServerSendsNoise(10000)
	assertClientClosedConnection(t)
}

func TestClient_PuzzleUnknownType(t *testing.T) {
	clientSetup()
	defer cleanup()

	sSend(t, &msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ + 1,
		Body:   [64]byte{},
		Param:  10,
	})
	assertClientClosedConnection(t)
}

func TestClient_PuzzleHugeDifficulty(t *testing.T) {
	clientSetup()
	defer cleanup()

	sSend(t, &msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ,
		Body:   [64]byte{},
		Param:  200,
	})
	assertClientClosedConnection(t)
}

func TestClient_PuzzleAnswersIt(t *testing.T) {
	clientSetup()
	defer cleanup()

	puzzleRequest = msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ,
		Param:  15,
	}
	copy(puzzleRequest.Body[:], cryptoutil.RandBytes(64)[:])
	sSend(t, &puzzleRequest)
	sRecv(t, &puzzleResponse)

	if !sha512lz.Verify(puzzleRequest.Body, puzzleResponse.Response, 15) {
		t.Error("client did not provide a correct solution to the puzzle")
	}
}

func TestClient_ClientHello(t *testing.T) {
	clientSetup()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	sRecv(t, &clientHello)

	if clientHello.Protocol != msg.ClientHelloProtocol {
		t.Error("client sent an unknown protocol")
	}
	if clientHello.WireType != msg.ClientHelloWireTypeSimpleAES256 &&
		clientHello.WireType != msg.ClientHelloWireTypeTripleAES256 {
		t.Error("Client sent an unknown wire type")
	}
	clientKey, err := cfg.GetKeyByID(cfg.ClientKey)
	if err != nil {
		t.Error("could not read key from config ... test is wrong", err)
	}
	if clientHello.KeyIdAsString() != clientKey.Uuid {
		t.Error("client did not send its key-id")
	}
}

// ----- givens ------------------------------------------------------------------------------------------------------

func givenClientSolvesPuzzle(t *testing.T) {
	puzzleRequest = msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ,
		Body:   [64]byte{},
		Param:  uint16(cfg.PuzzleDifficulty),
	}
	copy(puzzleRequest.Body[:], cryptoutil.RandBytes(64)[:])
	sSend(t, &puzzleRequest)
	sRecv(t, &puzzleResponse)
	if !sha512lz.Verify(puzzleRequest.Body, puzzleResponse.Response, cfg.PuzzleDifficulty) {
		t.Error("client did not provide a correct solution to the puzzle")
	}
}
