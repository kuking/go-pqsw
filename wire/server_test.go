package wire

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/logger"
	"github.com/kuking/go-pqsw/config"
	cu "github.com/kuking/go-pqsw/cryptoutil"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/kuking/go-pqsw/wire/sha512lz"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

//TODO: test for stale connections

var srvCfg *config.Config
var cliCfg *config.Config
var cPipe, sPipe net.Conn

var clientHello msg.ClientHello
var puzzleRequest msg.PuzzleRequest
var puzzleResponse msg.PuzzleResponse
var sharedSecretRequest msg.SharedSecretRequest
var sharedSecretBundleDescResponse msg.SharedSecretBundleDescriptionResponse

func setup() {
	logger.Init("test", true, false, os.Stdout)
	srvCfg = config.NewEmpty()
	srvCfg.PuzzleDifficulty = 10 // smaller value increases false positives in 'random/noise answer to the puzzle' tests
	cliCfg = config.NewEmpty()
	// 10 is pretty fast, no need to be specific about those tests at this time.
	cPipe, sPipe = net.Pipe()
}

func serverSetup() {
	setup()
	srvCfg.TripleAES256 = config.TripleAES256Disabled
	cliCfg.TripleAES256 = config.TripleAES256Disabled
	go ServerHandshake(sPipe, srvCfg)
}

func serverSetupWithTripleAES256() {
	setup()
	srvCfg.TripleAES256 = config.TripleAES256Required
	cliCfg.TripleAES256 = config.TripleAES256Required
	go ServerHandshake(sPipe, srvCfg)
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
	srvCfg = config.NewEmpty()
	srvCfg.PuzzleDifficulty = 12345
	cPipe, sPipe = net.Pipe()
	go ServerHandshake(sPipe, srvCfg)
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
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPuzzleAnswered(t)
	givenValidClientHello(t)
	clientHello.Protocol = 1234
	cSend(t, clientHello)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestServerClientHello_InvalidWireType(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPuzzleAnswered(t)
	givenValidClientHello(t)
	clientHello.WireType = 1234
	cSend(t, clientHello)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseProtocolRequestedNotSupported)
}

func TestServerClientHello_WireType_TripleAES256_Options(t *testing.T) {
	testCases := [][]config.TripleAES256Config{ // server, client, outcome
		{config.TripleAES256Required, config.TripleAES256Required, "triple"},
		{config.TripleAES256Required, config.TripleAES256Allowed, "triple"},
		{config.TripleAES256Required, config.TripleAES256Disabled, "server-disconnects-not-enough-security"},
		{config.TripleAES256Allowed, config.TripleAES256Required, "triple"},
		{config.TripleAES256Allowed, config.TripleAES256Allowed, "triple"},
		{config.TripleAES256Allowed, config.TripleAES256Disabled, "simple"},
		{config.TripleAES256Disabled, config.TripleAES256Required, "server-disconnects-too-much-security"},
		{config.TripleAES256Disabled, config.TripleAES256Allowed, "simple"},
		{config.TripleAES256Disabled, config.TripleAES256Disabled, "simple"},
	}
	for n, testCase := range testCases {
		t.Run(fmt.Sprintf("case=%v srv=%v cli=%v outcome=%v", n, testCase[0], testCase[1], testCase[2]),
			func(t *testing.T) {
				serverSetup()
				defer cleanup()
				srvCfg.TripleAES256 = testCase[0]
				cliCfg.TripleAES256 = testCase[1]
				outcome := testCase[2]
				givenPotpInConfig()
				givenServerAndClientKeys(cu.KeyTypeSidhFp434)
				givenPuzzleAnswered(t)
				givenValidClientHello(t)
				cSend(t, clientHello)
				if outcome == "server-disconnects-not-enough-security" {
					assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
				} else if outcome == "server-disconnects-too-much-security" {
					assertServerClosedConnectionWithCause(t, msg.DisconnectCauseTooMuchSecurityRequested)
				} else if outcome == "simple" {
					cRecv(t, &sharedSecretRequest)
					if sharedSecretRequest.WireType != msg.WireTypeSimpleAES256 {
						t.Errorf("expected server to decide to establish a SimpleAES256, we got: %v",
							sharedSecretRequest.WireType)
					}
				} else if outcome == "triple" {
					cRecv(t, &sharedSecretRequest)
					if sharedSecretRequest.WireType != msg.WireTypeTripleAES256 {
						t.Errorf("expected server to decide to establish a TripleAES256, we got: %v",
							sharedSecretRequest.WireType)
					}
				} else {
					t.Error("unimplemented yet")
				}
			})
	}
}

func TestServerClientHello_WireType_TripleAES256(t *testing.T) {
	serverSetupWithTripleAES256()
	defer cleanup()
	givenPotpInConfig()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPuzzleAnswered(t)
	givenValidClientHello(t)
	clientHello.WireType = msg.WireTypeTripleAES256
	cSend(t, clientHello)
	cRecv(t, &sharedSecretRequest)
	assertConnectionStillOpen(t)
}

func TestServerClientHello_ServerDisconnectsWhenTripleAES256Required(t *testing.T) {
	serverSetup()
	defer cleanup()
	srvCfg.TripleAES256 = config.TripleAES256Required
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPuzzleAnswered(t)
	givenValidClientHello(t)
	cSend(t, clientHello)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerClientHello_UnrecognizedKeyId(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPuzzleAnswered(t)
	givenValidClientHello(t)
	copy(clientHello.KeyId[5:], []byte{1, 2, 3, 4, 5, 6, 7, 8})
	cSend(t, clientHello)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseCounterpartyKeyIdNotRecognised)
}

func TestServerClientHello_SendsAndDisconnects(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPuzzleAnswered(t)
	givenValidClientHello(t)
	cSend(t, clientHello)
	_ = cPipe.Close()
	assertServerClosedConnection(t)
}

func TestServerClientHello_HappyPath(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenValidClientHello(t)
	cSend(t, clientHello)
	cRecv(t, &sharedSecretRequest)
	assertConnectionStillOpen(t)
}

func TestServerSharedSecretRequest_Disconnect(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	cRecv(t, &sharedSecretRequest)
	_ = cPipe.Close()
	assertServerClosedConnection(t)
}

func TestServerSharedSecretRequest_EmptyResponse(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
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
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	_, _, _, clientPotp := givenSharedSecretRequestReceived(t)

	cSend(t, msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.IdAs32Byte(),
		PotpOffset:   123,
		SecretsCount: 0,
		SecretSize:   500,
	})
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerSharedSecretRequest_InvalidPotpId(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp503)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	keySize, _, clientKey, _ := givenSharedSecretRequestReceived(t)
	kems := calculateKemsCount(clientKey, keySize)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   [32]byte{},
		PotpOffset:   123,
		SecretsCount: uint8(kems),
		SecretSize:   402,
	}
	cSend(t, sharedSecretBundleDescResponse)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCausePotpNotRecognised)
}

func TestServerSharedSecretRequest_InsufficientSharedSecrets(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)

	keySize, _, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	kemsCount := calculateKemsCount(clientKey, keySize)
	cSend(t, msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.IdAs32Byte(),
		PotpOffset:   123,
		SecretsCount: uint8(kemsCount + 1),
		SecretSize:   uint16(cu.CipherTextSizeByKeyType[cu.KeyTypeSidhFp434].CipherText),
	})

	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerSharedSecretRequest_EmptyCiphertexts(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()

	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	keySize, _, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	clientSecretsCount := calculateKemsCount(clientKey, keySize)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.IdAs32Byte(),
		PotpOffset:   0,
		SecretsCount: uint8(clientSecretsCount),
		SecretSize:   uint16(cu.CipherTextSizeByKeyType[cu.KeyTypeSidhFp434].CipherText),
	}
	cSend(t, sharedSecretBundleDescResponse)

	for secretNo := 0; secretNo < clientSecretsCount; secretNo++ {
		ciphertext := make([]byte, cu.CipherTextSizeByKeyType[cu.KeyTypeSidhFp434].CipherText)
		cSend(t, ciphertext)
	}

	cRecv(t, &sharedSecretBundleDescResponse) // implies the server is happy with the message
}

func TestServerShareSecretRequest_ClientSendsInvalidSizeKem(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()

	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	keySize, _, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	clientSecretsCount := calculateKemsCount(clientKey, keySize)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   clientPotp.IdAs32Byte(),
		PotpOffset:   0,
		SecretsCount: uint8(clientSecretsCount),
		SecretSize:   uint16(cu.CipherTextSizeByKeyType[cu.KeyTypeSidhFp434].CipherText + 25),
	}

	cSend(t, sharedSecretBundleDescResponse)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerShareSecretRequest_ClientSendsNoiseKemItShouldNotPanic(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()

	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	givenSharedSecretRequestReceived(t)
	ClientSendsNoise(10000)
	assertServerClosedConnectionWithCause(t, msg.DisconnectCauseNotEnoughSecurityRequested)
}

func TestServerSharedSecretRequest_ClientSendsSharedSecretServerACK(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	keySize, serverKey, _, clientPotp := givenSharedSecretRequestReceived(t)

	givenSharedSecretSend(t, cSend, serverKey, clientPotp, keySize)
	cRecv(t, &sharedSecretBundleDescResponse) // implies the server is happy with the message
}

func TestServerSharedSecretRequest_ClientAndServerExchangeSharedSecret(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	keySize, serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	fullClientKey, _ := cliCfg.GetKeyByCN(clientKey.CN)

	givenSharedSecretSend(t, cSend, serverKey, clientPotp, keySize)

	cRecv(t, &sharedSecretBundleDescResponse) // implies the server is happy with the message
	ciphertext := make([]byte, sharedSecretBundleDescResponse.SecretSize)
	if cu.CipherTextSizeByKeyType[serverKey.GetKeyType()].CipherText != len(ciphertext) {
		t.Error("secret size sent by server is wrong")
	}
	for i := 0; i < int(sharedSecretBundleDescResponse.SecretsCount); i++ {
		cRecv(t, ciphertext)
		_, err := cu.Dencapsulate(
			fullClientKey.PubBytes(), fullClientKey.PvtBytes(), ciphertext, clientKey.GetKeyType())
		if err != nil {
			t.Error("kem failed to decapsulate", err)
		}
	}
	assertConnectionStillOpen(t)
}

func TestServer_SecureWireSetup(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	keySize, serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	fullClientKey, _ := cliCfg.GetKeyByCN(clientKey.CN)

	clientShare := givenSharedSecretSend(t, cSend, serverKey, clientPotp, keySize)
	serverShare := givenSharedSecretReceive(t, cRecv, fullClientKey, clientPotp, keySize)

	sharedKey := mixSharedSecretsForKey(serverShare, clientShare, keySize) // FIXME: method is not being tested ...
	_, err := NewSecureWireAES256CGM(sharedKey[0:32], sharedKey[32:32+12], cPipe, serverKey.IdAs32Byte(), clientKey.IdAs32Byte())
	if err != nil {
		t.Errorf("could not establish secure_wire, error=%v", err)
	}
}

func TestServer_SecureWriteGoodMessageInvalid(t *testing.T) {
	serverSetup()
	defer cleanup()
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	keySize, serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	fullClientKey, _ := cliCfg.GetKeyByCN(clientKey.CN)
	clientShare := givenSharedSecretSend(t, cSend, serverKey, clientPotp, keySize)
	serverShare := givenSharedSecretReceive(t, cRecv, fullClientKey, clientPotp, keySize)
	sharedKey := mixSharedSecretsForKey(serverShare, clientShare, keySize)
	sw, err := NewSecureWireAES256CGM(sharedKey[0:32], sharedKey[32:32+12], cPipe, serverKey.IdAs32Byte(), clientKey.IdAs32Byte())
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
	givenServerAndClientKeys(cu.KeyTypeSidhFp434)
	givenPotpInConfig()
	givenPuzzleAnswered(t)
	givenClientHelloAnswered(t)
	keySize, serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
	fullClientKey, _ := cliCfg.GetKeyByCN(clientKey.CN)
	clientShare := givenSharedSecretSend(t, cSend, serverKey, clientPotp, keySize)
	serverShare := givenSharedSecretReceive(t, cRecv, fullClientKey, clientPotp, keySize)
	sharedKey := mixSharedSecretsForKey(serverShare, clientShare, keySize)
	sw, err := NewSecureWireAES256CGM(sharedKey[0:32], sharedKey[32:32+12], cPipe, serverKey.IdAs32Byte(), clientKey.IdAs32Byte())
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

func TestServer_HappyPath_forEvery_KeyType(t *testing.T) {
	for keyType, name := range cu.KeyTypeAsString {
		t.Run(fmt.Sprintf("Happy Path using %v", name), func(t *testing.T) {
			serverSetup()
			givenServerAndClientKeys(keyType)
			givenPotpInConfig()
			givenPuzzleAnswered(t)
			givenClientHelloAnswered(t)
			keySize, serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
			fullClientKey, _ := cliCfg.GetKeyByCN(clientKey.CN)
			clientShare := givenSharedSecretSend(t, cSend, serverKey, clientPotp, keySize)
			serverShare := givenSharedSecretReceive(t, cRecv, fullClientKey, clientPotp, keySize)
			sharedKey := mixSharedSecretsForKey(serverShare, clientShare, keySize)
			sw, err := NewSecureWireAES256CGM(sharedKey[0:32], sharedKey[32:32+12], cPipe, serverKey.IdAs32Byte(), clientKey.IdAs32Byte())
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
			cleanup()
		})
	}
}

func TestServer_HappyPath_forEvery_KeyType_UsingTripleAES256(t *testing.T) {
	for keyType, name := range cu.KeyTypeAsString {
		t.Run(fmt.Sprintf("Happy Path using %v", name), func(t *testing.T) {
			serverSetupWithTripleAES256()
			givenServerAndClientKeys(keyType)
			givenPotpInConfig()
			givenPuzzleAnswered(t)
			givenClientHelloAnswered(t)
			keySize, serverKey, clientKey, clientPotp := givenSharedSecretRequestReceived(t)
			fullClientKey, _ := cliCfg.GetKeyByCN(clientKey.CN)
			clientShare := givenSharedSecretSend(t, cSend, serverKey, clientPotp, keySize)
			serverShare := givenSharedSecretReceive(t, cRecv, fullClientKey, clientPotp, keySize)
			sharedKey := mixSharedSecretsForKey(serverShare, clientShare, keySize)

			ofs := 0
			oneKeySize := 32
			oneNonceSize := 12
			sw2, err := NewSecureWireAES256CGM(sharedKey[ofs:ofs+oneKeySize], sharedKey[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], cPipe, serverKey.IdAs32Byte(), clientKey.IdAs32Byte())
			if err != nil {
				t.Error(err)
			}
			ofs += oneKeySize + oneNonceSize
			sw1, err := NewSecureWireAES256CGM(sharedKey[ofs:ofs+oneKeySize], sharedKey[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], sw2, serverKey.IdAs32Byte(), clientKey.IdAs32Byte())
			if err != nil {
				t.Error(err)
			}
			ofs += oneKeySize + oneNonceSize
			sw, err := NewSecureWireAES256CGM(sharedKey[ofs:ofs+oneKeySize], sharedKey[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], sw1, serverKey.IdAs32Byte(), clientKey.IdAs32Byte())
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
			cleanup()
		})
	}
}

// ----- givens ------------------------------------------------------------------------------------------------------

func givenServerAndClientKeys(keyType cu.KeyType) {
	sKey, _ := srvCfg.CreateAndAddKey(keyType, "S1")
	srvCfg.PreferredKeyCN = sKey.CN

	cKey, _ := cliCfg.CreateAndAddKey(keyType, "C1")
	cliCfg.PreferredKeyCN = cKey.CN

	sKey.Pvt = ""
	cKey.Pvt = ""
	srvCfg.Keys = append(srvCfg.Keys, *cKey)
	cliCfg.Keys = append(cliCfg.Keys, *sKey)
}

func givenPotpInConfig() {
	potp, _ := srvCfg.CreateAndAddInPlacePotp(4096, "P1")
	srvCfg.PreferredPotpCN = potp.CN
	cliCfg.Potps = append(cliCfg.Potps, *potp)
	cliCfg.PreferredPotpCN = potp.CN
}

func givenPuzzleAnswered(t *testing.T) {
	cRecv(t, &puzzleRequest)
	puzzleResponse.Response = sha512lz.Solve(puzzleRequest.Body, int(puzzleRequest.Param))
	cSend(t, &puzzleResponse)
}

func givenValidClientHello(t *testing.T) {
	key, _ := cliCfg.GetKeyByCN(cliCfg.PreferredKeyCN)
	clientHello = msg.ClientHello{
		KeyId:    key.IdAs32Byte(),
		Protocol: msg.ClientHelloProtocol,
	}
	switch cliCfg.TripleAES256 {
	case config.TripleAES256Allowed:
		clientHello.WireType = msg.WireTypeTripleAES256Optional
	case config.TripleAES256Required:
		clientHello.WireType = msg.WireTypeTripleAES256
	case config.TripleAES256Disabled:
		clientHello.WireType = msg.WireTypeSimpleAES256
	default:
		t.Error("client config TripleAES256 entry unknown, please implement.")
	}
}

func givenClientHelloAnswered(t *testing.T) {
	givenValidClientHello(t)
	cSend(t, clientHello)
}

func givenSharedSecretRequestReceived(t *testing.T) (keySize int, serverKey *config.Key, clientKey *config.Key, clientPotp *config.Potp) {
	cRecv(t, &sharedSecretRequest)
	if sharedSecretRequest.RequestType != msg.SharedSecretRequestTypeKEMAndPotp {
		t.Error("sharedSecretRequest.RequestType should be 0, as so far the only version implemented")
	}
	serverKey, _ = srvCfg.GetKeyByID(sharedSecretRequest.KeyIdPreferredAsString())
	if serverKey.CN != srvCfg.PreferredKeyCN {
		t.Error("server sent another key")
	}
	clientKey, _ = srvCfg.GetKeyByCN(cliCfg.PreferredKeyCN) // XXX: CROSS CHECK  THIS
	clientPotp, _ = srvCfg.GetPotpByCN(cliCfg.PreferredPotpCN)
	keySize = 256/8 + 96/8
	if sharedSecretRequest.WireType == msg.WireTypeTripleAES256 {
		keySize *= 3
	}
	return
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
	return sendNoise(sPipe, minimumAmount)
}

func givenSharedSecretSend(t *testing.T, send func(t *testing.T, msg interface{}), receiverKey *config.Key, potp *config.Potp, keySize int) *msg.SharedSecret {
	clientSecretsCount := calculateKemsCount(receiverKey, keySize)
	potpBytes, otpOffset := potp.PickOTP(keySize)

	sharedSecretBundleDescResponse = msg.SharedSecretBundleDescriptionResponse{
		PotpIdUsed:   potp.IdAs32Byte(),
		PotpOffset:   otpOffset,
		SecretsCount: uint8(clientSecretsCount),
		SecretSize:   uint16(cu.CipherTextSizeByKeyType[receiverKey.GetKeyType()].CipherText),
	}
	send(t, sharedSecretBundleDescResponse)

	sharedSecret := msg.SharedSecret{
		Otp:    potpBytes,
		Shared: make([][]byte, clientSecretsCount),
	}
	for secretNo := 0; secretNo < clientSecretsCount; secretNo++ {
		var ciphertext []byte
		var err error
		ciphertext, sharedSecret.Shared[secretNo], err =
			cu.Encapsulate(receiverKey.PubBytes(), receiverKey.GetKeyType())
		if err != nil {
			panic(err)
		}
		send(t, ciphertext)
	}
	return &sharedSecret
}

func givenSharedSecretReceive(t *testing.T, recv func(t *testing.T, msg interface{}), receiverKey *config.Key, expectedPotp *config.Potp, keySize int) *msg.SharedSecret {
	recv(t, &sharedSecretBundleDescResponse)
	if expectedPotp != nil {
		clientPotpId := expectedPotp.IdAs32Byte()
		if !bytes.Equal(sharedSecretBundleDescResponse.PotpIdUsed[:], clientPotpId[:]) {
			t.Error("Server is asking to use another potp ... which MIGHT be fine, but it is not implemented so far, it should not")
		}
	}
	potp, err := srvCfg.GetPotpByID(sharedSecretBundleDescResponse.PotpIdAsString())
	if err != nil {
		t.Errorf("failed to retrieve potp id %v, err=%v", sharedSecretBundleDescResponse.PotpIdAsString(), err)
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
	if cu.CipherTextSizeByKeyType[receiverKey.GetKeyType()].CipherText != len(ciphertext) {
		t.Error("secret size sent by server is wrong")
	}
	for i := 0; i < int(sharedSecretBundleDescResponse.SecretsCount); i++ {
		recv(t, ciphertext)
		sharedSecret.Shared[i], err = cu.Dencapsulate(receiverKey.PubBytes(), receiverKey.PvtBytes(), ciphertext, receiverKey.GetKeyType())
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
	//if c, err := conn.Read(one); err == nil {
	//	t.Fatalf("pipe should have disconnected. But read count: %v", c)
	//}
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

func calculateKemsCount(clientKey *config.Key, keySize int) (secretsCount int) {
	sharedSecretBytes := cu.CipherTextSizeByKeyType[clientKey.GetKeyType()].SharedSecret
	secretsCount = keySize / sharedSecretBytes
	if (keySize % sharedSecretBytes) != 0 {
		secretsCount += 1
	}
	return secretsCount
}
