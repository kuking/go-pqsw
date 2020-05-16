package wire

import (
	"github.com/kuking/go-pqsw/wire/msg"
	"testing"
)

// most of common asserts, givens, etc. in server_test.go
func clientSetup() {
	setup()
	go NewServerHandshake(cPipe, cfg)
}

func TestClient_ConnectWithNoise(t *testing.T) {
	clientSetup()
	defer cleanup()

	ServerSendsNoise(10000)
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
