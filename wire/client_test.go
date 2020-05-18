package wire

import (
	"bytes"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"testing"
)

// most of common asserts, givens, etc. in server_test.go
func clientSetup() {
	setup()
	givenServerAndClientKeys()
	givenPotpInConfig()
	go ClientHandshake(cPipe, cfg)
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

func TestClient_PuzzleHugeDifficultyDisconnects(t *testing.T) {
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

func TestClient_ServerShareSecretRequest_InvalidRequestType(t *testing.T) {
	clientSetup()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	givenClientHello(t)

	sharedSecretRequest = msg.SharedSecretRequest{
		RequestType: msg.SharedSecretRequestTypeKEMAndPotp + 123,
		KeyId:       [32]byte{},
	}
	sSend(t, &sharedSecretRequest)
	assertClientClosedConnection(t)
}

func TestClient_ServerShareSecretRequest_InvalidServerKey(t *testing.T) {
	clientSetup()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	givenClientHello(t)

	srvKeyBytes := [32]byte{}
	copy(srvKeyBytes[:], cryptoutil.RandBytes(32))
	sharedSecretRequest = msg.SharedSecretRequest{
		RequestType: msg.SharedSecretRequestTypeKEMAndPotp,
		KeyId:       srvKeyBytes,
	}
	sSend(t, &sharedSecretRequest)
	assertClientClosedConnection(t)
}

func TestClient_ServerShareSecretRequest_andResponse(t *testing.T) {
	clientSetup()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	_, keySize := givenClientHello(t)
	serverKey := givenServerShareRequest(t)

	givenSharedSecretReceive(t, sRecv, serverKey, nil, keySize)
}

func TestClient_ShareSecretsExchange(t *testing.T) {
	clientSetup()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	clientKey, keySize := givenClientHello(t)
	serverKey := givenServerShareRequest(t)
	potp, err := cfg.GetPotpByID(cfg.ServerPotp)
	if err != nil {
		t.Errorf("could not retrieve potp, err=%v", err)
	}

	clientShare := givenSharedSecretReceive(t, sRecv, serverKey, nil, keySize)
	serverShare := givenSharedSecretSend(t, sSend, clientKey, potp)
	keysBytes := mixSharedSecretsForKey(serverShare, clientShare, keySize)

	_, err = NewSecureWireAES256CGM(keysBytes[0:32], keysBytes[32:32+12], sPipe)
	if err != nil {
		t.Error(err)
	}
}

func TestClient_SecureWireHandshakeIssues(t *testing.T) {
	clientSetup()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	clientKey, keySize := givenClientHello(t)
	serverKey := givenServerShareRequest(t)
	potp, err := cfg.GetPotpByID(cfg.ServerPotp)
	if err != nil {
		t.Errorf("could not retrieve potp, err=%v", err)
	}

	clientShare := givenSharedSecretReceive(t, sRecv, serverKey, nil, keySize)
	serverShare := givenSharedSecretSend(t, sSend, clientKey, potp)
	keysBytes := mixSharedSecretsForKey(serverShare, clientShare, keySize)

	sw, err := NewSecureWireAES256CGM(keysBytes[0:32], keysBytes[32:32+12], sPipe)
	if err != nil {
		t.Error(err)
	}
	_, err = sw.Write([]byte{'N', 'O', 'G', 'O', 'O', 'D'})
	if err != nil {
		t.Error(err)
	}
	assertClientClosedConnection(t)
}

func TestClient_HappyPath(t *testing.T) {
	clientSetup()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	clientKey, keySize := givenClientHello(t)
	serverKey := givenServerShareRequest(t)
	potp, err := cfg.GetPotpByID(cfg.ServerPotp)
	if err != nil {
		t.Errorf("could not retrieve potp, err=%v", err)
	}

	clientShare := givenSharedSecretReceive(t, sRecv, serverKey, nil, keySize)
	serverShare := givenSharedSecretSend(t, sSend, clientKey, potp)
	keysBytes := mixSharedSecretsForKey(serverShare, clientShare, keySize)

	sw, err := NewSecureWireAES256CGM(keysBytes[0:32], keysBytes[32:32+12], sPipe)
	if err != nil {
		t.Error(err)
	}
	_, _ = sw.Write([]byte{'G', 'O', 'O', 'D'})
	gb := make([]byte, 4)
	n, err := sw.Read(gb)
	if n != 4 || err != nil || !bytes.Equal(gb[:], []byte{'G', 'O', 'O', 'D'}) {
		t.Error("error reading final secure_wire good confirmation")
	}
	assertConnectionStillOpen(t)
}

// ----- givens ------------------------------------------------------------------------------------------------------

func givenClientHello(t *testing.T) (clientKey *config.Key, keySize int) {
	sRecv(t, &clientHello)
	clientKey, _ = cfg.GetKeyByID(clientHello.KeyIdAsString())
	keySize = calculateKeySize(&clientHello)
	return
}

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

func givenServerShareRequest(t *testing.T) (serverKey *config.Key) {
	serverKey, err := cfg.GetKeyByID(cfg.ServerKey)
	if err != nil {
		t.Errorf("could not retrieve server key from config, this is a bug in the test, err=%v", err)
	}
	sharedSecretRequest = msg.SharedSecretRequest{
		RequestType: msg.SharedSecretRequestTypeKEMAndPotp,
		KeyId:       serverKey.GetKeyIdAs32Byte(),
	}
	sSend(t, &sharedSecretRequest)
	return
}
