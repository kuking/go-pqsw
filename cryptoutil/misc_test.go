package cryptoutil

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestEncB64(t *testing.T) {
	origBytes := RandBytes(1024)
	base64str := EncB64(origBytes)
	decodedBytes, err := base64.StdEncoding.DecodeString(base64str)
	if err != nil {
		t.Error(err)
	}
	if !bytes.Equal(origBytes, decodedBytes) {
		t.Error("Decoded was not equal")
	}
}
