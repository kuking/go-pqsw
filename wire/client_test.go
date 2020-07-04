package wire

import (
	"bytes"
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"testing"
)

// most of common asserts, givens, etc. in server_test.go
func clientSetup() {
	setup()
	srvCfg.TripleAES256 = config.TripleAES256Disabled
	cliCfg.TripleAES256 = config.TripleAES256Disabled
	givenServerAndClientKeys(cryptoutil.KeyTypeSidhFp503) //XXX FIXME test with multiple keys types
	givenPotpInConfig()
	go ClientHandshake(cPipe, cliCfg)
}

func clientSetupWithTripleAES256() {
	setup()
	srvCfg.TripleAES256 = config.TripleAES256Required
	cliCfg.TripleAES256 = config.TripleAES256Required
	givenServerAndClientKeys(cryptoutil.KeyTypeSidhFp434)
	givenPotpInConfig()
	go ClientHandshake(cPipe, cliCfg)
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
	if clientHello.WireType != msg.WireTypeSimpleAES256 &&
		clientHello.WireType != msg.WireTypeTripleAES256 &&
		clientHello.WireType != msg.WireTypeTripleAES256Optional {
		t.Error("Client sent an unknown wire type")
	}
	clientKey, err := cliCfg.GetKeyByCN(cliCfg.PreferredKeyCN)
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
		WireType:    msg.WireTypeSimpleAES256,
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
		WireType:    msg.WireTypeSimpleAES256,
	}
	sSend(t, &sharedSecretRequest)
	assertClientClosedConnection(t)
}

func TestClient_ServerShareSecretRequest_TripleAES256Required_ServerInsistOnSingleAES256(t *testing.T) {
	clientSetup()
	cliCfg.TripleAES256 = config.TripleAES256Required
	defer cleanup()

	givenClientSolvesPuzzle(t)
	givenClientHello(t)

	serverKey, _ := srvCfg.GetKeyByCN(srvCfg.PreferredKeyCN)
	sharedSecretRequest = msg.SharedSecretRequest{
		RequestType: msg.SharedSecretRequestTypeKEMAndPotp,
		KeyId:       serverKey.IdAs32Byte(),
		WireType:    msg.WireTypeSimpleAES256,
	}
	sSend(t, &sharedSecretRequest)
	assertClientClosedConnection(t)
}

func TestClient_ServerShareSecretRequest_SimpleAES256_ServerInsistOnTripleAES256(t *testing.T) {
	clientSetup()
	cliCfg.TripleAES256 = config.TripleAES256Disabled
	defer cleanup()

	givenClientSolvesPuzzle(t)
	givenClientHello(t)

	serverKey, _ := srvCfg.GetKeyByCN(srvCfg.PreferredKeyCN)
	sharedSecretRequest = msg.SharedSecretRequest{
		RequestType: msg.SharedSecretRequestTypeKEMAndPotp,
		KeyId:       serverKey.IdAs32Byte(),
		WireType:    msg.WireTypeTripleAES256,
	}
	sSend(t, &sharedSecretRequest)
	assertClientClosedConnection(t)
}

func TestClient_ServerShareSecretRequest_andResponse(t *testing.T) {
	clientSetup()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	_, keySize := givenClientHello(t)
	clientKey := givenServerShareRequest(t)

	givenSharedSecretReceive(t, sRecv, clientKey, nil, keySize)
}

func TestClient_ShareSecretsExchange(t *testing.T) {
	clientSetup()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	clientKey, keySize := givenClientHello(t)
	serverKey := givenServerShareRequest(t)
	potp, err := cliCfg.GetPotpByCN(cliCfg.PreferredPotpCN)
	if err != nil {
		t.Errorf("could not retrieve potp, err=%v", err)
	}

	clientShare := givenSharedSecretReceive(t, sRecv, clientKey, nil, keySize)
	serverShare := givenSharedSecretSend(t, sSend, clientKey, potp, keySize)
	keysBytes := mixSharedSecretsForKey(serverShare, clientShare, keySize)

	_, err = NewSecureWireAES256CGM(keysBytes[0:32], keysBytes[32:32+12], sPipe, clientKey.IdAs32Byte(), serverKey.IdAs32Byte())
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
	potp, err := cliCfg.GetPotpByCN(cliCfg.PreferredPotpCN)
	if err != nil {
		t.Errorf("could not retrieve potp, err=%v", err)
	}

	clientShare := givenSharedSecretReceive(t, sRecv, clientKey, nil, keySize)
	serverShare := givenSharedSecretSend(t, sSend, clientKey, potp, keySize)
	keysBytes := mixSharedSecretsForKey(serverShare, clientShare, keySize)

	sw, err := NewSecureWireAES256CGM(keysBytes[0:32], keysBytes[32:32+12], sPipe, clientKey.IdAs32Byte(), serverKey.IdAs32Byte())
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
	potp, err := cliCfg.GetPotpByCN(cliCfg.PreferredPotpCN)
	if err != nil {
		t.Errorf("could not retrieve potp, err=%v", err)
	}

	clientShare := givenSharedSecretReceive(t, sRecv, serverKey, nil, keySize)
	serverShare := givenSharedSecretSend(t, sSend, clientKey, potp, keySize)
	keysBytes := mixSharedSecretsForKey(serverShare, clientShare, keySize)

	sw, err := NewSecureWireAES256CGM(keysBytes[0:32], keysBytes[32:32+12], sPipe, clientKey.IdAs32Byte(), serverKey.IdAs32Byte())
	if err != nil {
		t.Error(err)
	}
	_, err = sw.Write([]byte{'G', 'O', 'O', 'D'})
	if err != nil {
		t.Error(err)
	}
	gb := make([]byte, 4)
	n, err := sw.Read(gb)
	if n != 4 || err != nil || !bytes.Equal(gb[:], []byte{'G', 'O', 'O', 'D'}) {
		t.Error("error reading final secure_wire good confirmation")
	}
	assertConnectionStillOpen(t)
}

func TestClient_HappyPath_TripleAES256(t *testing.T) {
	clientSetupWithTripleAES256()
	defer cleanup()

	givenClientSolvesPuzzle(t)
	clientKey, keySize := givenClientHello(t)
	serverKey := givenServerShareRequest(t)
	potp, err := cliCfg.GetPotpByCN(cliCfg.PreferredPotpCN)
	if err != nil {
		t.Errorf("could not retrieve potp, err=%v", err)
	}

	clientShare := givenSharedSecretReceive(t, sRecv, serverKey, nil, keySize)
	serverShare := givenSharedSecretSend(t, sSend, clientKey, potp, keySize)
	keysBytes := mixSharedSecretsForKey(serverShare, clientShare, keySize)
	fmt.Println("TestClient_HappyPath_TripleAES256, keyBytes:", cryptoutil.EncB64(keysBytes))

	ofs := 0
	oneKeySize := 32
	oneNonceSize := 12
	sw2, err := NewSecureWireAES256CGM(keysBytes[ofs:ofs+oneKeySize], keysBytes[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], sPipe, clientKey.IdAs32Byte(), serverKey.IdAs32Byte())
	if err != nil {
		t.Error(err)
	}
	ofs += oneKeySize + oneNonceSize
	sw1, err := NewSecureWireAES256CGM(keysBytes[ofs:ofs+oneKeySize], keysBytes[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], sw2, clientKey.IdAs32Byte(), serverKey.IdAs32Byte())
	if err != nil {
		t.Error(err)
	}
	ofs += oneKeySize + oneNonceSize
	sw, err := NewSecureWireAES256CGM(keysBytes[ofs:ofs+oneKeySize], keysBytes[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], sw1, clientKey.IdAs32Byte(), serverKey.IdAs32Byte())
	if err != nil {
		t.Error(err)
	}
	_, err = sw.Write([]byte{'G', 'O', 'O', 'D'})
	if err != nil {
		t.Error(err)
	}
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
	clientKey, _ = cliCfg.GetKeyByID(clientHello.KeyIdAsString())
	keySize = calculateSymmetricKeySize(&clientHello, srvCfg)
	return
}

func givenClientSolvesPuzzle(t *testing.T) {
	puzzleRequest = msg.PuzzleRequest{
		Puzzle: msg.PuzzleSHA512LZ,
		Body:   [64]byte{},
		Param:  uint16(srvCfg.PuzzleDifficulty),
	}
	copy(puzzleRequest.Body[:], cryptoutil.RandBytes(64)[:])
	sSend(t, &puzzleRequest)
	sRecv(t, &puzzleResponse)
	if !sha512lz.Verify(puzzleRequest.Body, puzzleResponse.Response, srvCfg.PuzzleDifficulty) {
		t.Error("client did not provide a correct solution to the puzzle")
	}
}

func givenServerShareRequest(t *testing.T) (serverKey *config.Key) {
	serverKey, err := srvCfg.GetKeyByCN(srvCfg.PreferredKeyCN)
	if err != nil {
		t.Errorf("could not retrieve server key from config, this is a bug in the test, err=%v", err)
	}
	sharedSecretRequest = msg.SharedSecretRequest{
		RequestType: msg.SharedSecretRequestTypeKEMAndPotp,
		KeyId:       serverKey.IdAs32Byte(),
		WireType:    msg.WireTypeSimpleAES256,
	}
	if srvCfg.TripleAES256 == config.TripleAES256Required {
		sharedSecretRequest.WireType = msg.WireTypeTripleAES256
	}
	sSend(t, &sharedSecretRequest)
	return
}
