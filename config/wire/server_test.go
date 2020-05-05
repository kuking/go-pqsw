package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/kuking/go-pqsw/config"
	"io"
	"net"
	"os"
	"testing"
)

//TODO: test for stale connections

var cfg *config.Config
var cPipe, sPipe net.Conn
var b []byte
var knockKnock KnockKnock
var hashRequest HashRequest

func beforeEach() {
	fmt.Printf("beforeEach")
	cfg = config.NewEmpty()
	cPipe, sPipe = net.Pipe()
	b = make([]byte, 0)
	knockKnock = KnockKnock{
		KeyId:           [32]byte{},
		ProtocolVersion: 0,
		WireType:        0,
	}
	go newClientHandshake(sPipe, cfg)
}

func teardown() {
	cPipe.Close()
	sPipe.Close()
	cfg = nil
	b = nil
}

func TestKnockKnock_EmptyPayload(t *testing.T) {
	send(t, knockKnock)
	assertServerClosedConnection(t)
}

func TestKnockKnock_HappyPath(t *testing.T) {

	givenValidKnockKnock()
	//send(t, knockKnock)

	//TODO
	//recv(t, hashRequest)
	//fmt.Printf("Client Received HashRequest: %v", hashRequest)

}

func givenValidKnockKnock() {
	keyId, err := cfg.CreateAndAddKey(config.KeyTypeSidhFp503)
	if err != nil {
		panic(err)
	}
	key, err := cfg.GetKeyByID(*keyId)
	knockKnock = KnockKnock{
		KeyId:           key.GetKeyIdAs32Byte(),
		ProtocolVersion: 1,
		WireType:        1,
	}
	fmt.Printf("TEST: Happy Valid KnockKnock with Key: %v\n", *keyId)
}

// --- common assertions ---

func assertServerClosedConnection(t *testing.T) {
	_, err := cPipe.Read(b)
	if err != io.EOF {
		t.Fatalf("Server should have disconnected, instead we got: %v", err.Error())
	}
}

// --- utility methods ---

func printMessage(msg interface{}) {
	var buf bytes.Buffer
	binary.Write(io.Writer(&buf), binary.LittleEndian, msg)
	fmt.Printf("Msg: %v \nLen: %d \nHex: %v\n", buf.Bytes(), len(buf.Bytes()), hex.EncodeToString(buf.Bytes()))
}

func send(t *testing.T, msg interface{}) {
	err := binary.Write(cPipe, binary.LittleEndian, msg)
	if err != nil {
		t.Errorf("Client->Server failed to send with: %v", err)
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
	code := m.Run()
	teardown()
	os.Exit(code)
}
