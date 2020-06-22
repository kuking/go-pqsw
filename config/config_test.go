package config

import (
	"bytes"
	"encoding/gob"
	"github.com/kuking/go-pqsw/cryptoutil"
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func TestNewEmpty(t *testing.T) {
	config := NewEmpty()
	if len(config.Keys) != 0 || len(config.Potps) != 0 {
		t.Fatal("New Config should be empty")
	}
	if config.PuzzleDifficulty == 0 {
		t.Fatal("It should set the PuzzleDifficulty")
	}
}

func TestLoadSaveRoundTrip(t *testing.T) {
	tmpFile, err := ioutil.TempFile("", "config")
	if err != nil {
		t.Fatal(err)
	}
	defer removeTempFile(tmpFile)

	original := NewEmpty()
	_, err = original.CreateAndAddKey(cryptoutil.KeyTypeSidhFp503, "1")
	fatalOnErr(t, err)
	_, err = original.CreateAndAddKey(cryptoutil.KeyTypeSidhFp751, "2")
	fatalOnErr(t, err)
	err = original.SaveTo(tmpFile.Name())
	fatalOnErr(t, err)

	loaded, err := LoadFromInteractive(tmpFile.Name())
	fatalOnErr(t, err)

	var originalBytes bytes.Buffer
	var loadedBytes bytes.Buffer
	if gob.NewEncoder(io.Writer(&originalBytes)).Encode(original) != nil ||
		gob.NewEncoder(io.Writer(&loadedBytes)).Encode(loaded) != nil {
		t.Fatal("Failed to create binary representations")
	}

	if originalBytes.String() != loadedBytes.String() {
		t.Fatal("Differences between stored and loaded config")
	}

}

func fatalOnErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func removeTempFile(file *os.File) {
	err := os.Remove(file.Name())
	if err != nil {
		panic(err)
	}
}
