package config

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func TestNewEmpty(t *testing.T) {
	config := NewEmpty()
	if len(config.Keys) != 0 || len(config.Otps) != 0 || len(config.Uniques) != 0 {
		t.Fatal("New Config should be empty")
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "config")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	//XXX: add extra entries in the config file

	original := NewEmpty()
	err = original.SaveTo(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadFrom(tmpFile.Name())

	var originalBytes bytes.Buffer
	var loadedBytes bytes.Buffer
	if binary.Write(io.Writer(&originalBytes), binary.LittleEndian, original) != nil ||
		binary.Write(io.Writer(&loadedBytes), binary.LittleEndian, loaded) != nil {
		t.Fatal("Failed to create binary representations")
	}

	if originalBytes.String() != loadedBytes.String() {
		t.Fatal("Differences between stored and loaded config")
	}

}
