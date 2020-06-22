package cryptoutil

import (
	"bytes"
	"golang.org/x/crypto/scrypt"
	"testing"
	"time"
)

func TestSimpleSuperTripleEncryptDecrypt_RoundTrip(t *testing.T) {
	password := "a password"
	plainText := []byte("This is a plainText")
	cipherText, err := SimpleSuperTripleEncrypt(plainText, password)
	if err != nil {
		t.Error(err)
	}

	if len(plainText)+100 > len(cipherText) {
		t.Error("It does not looks like there is an envelop, AEAD, checksum, iv, etc.")
	}

	plainTextRecovered, err := SimpleSuperTripleDecrypt(cipherText, password)
	if err != nil {
		t.Error(err)
	}
	if bytes.Equal(cipherText, plainTextRecovered) {
		t.Error("Recovered plainText not valid")
	}
}

func TestSimpleSuperTripleEncryptDecrypt_100k_RoundTrip(t *testing.T) {
	password := "a password"
	plainText := RandBytes(100 * 1024)
	cipherText, err := SimpleSuperTripleEncrypt(plainText, password)
	if err != nil {
		t.Error(err)
	}
	plainTextRecovered, err := SimpleSuperTripleDecrypt(cipherText, password)
	if err != nil {
		t.Error(err)
	}
	if bytes.Equal(cipherText, plainTextRecovered) {
		t.Error("Recovered plainText not valid")
	}
}

func TestSimpleSuperTripleEncryptDecrypt_CorruptedByteShouldErr(t *testing.T) {
	password := "a password"
	plainText := []byte("a plain text")
	cipherText, err := SimpleSuperTripleEncrypt(plainText, password)
	if err != nil {
		t.Error(err)
	}
	originalN := CurrentSCryptParameters.N
	CurrentSCryptParameters.N = 2
	for i := 0; i < len(cipherText); i++ {
		// it is important to do it at any byte
		corruptedCipherText := make([]byte, len(cipherText))
		if copy(corruptedCipherText, cipherText) != len(cipherText) {
			t.Error("Could not copy the cipherText")
		}
		corruptedCipherText[i]++
		_, err = SimpleSuperTripleDecrypt(corruptedCipherText, password)
		if err == nil {
			t.Errorf("corrupted cipher-text should have been detected, offset: %v", i)
		}
	}
	CurrentSCryptParameters.N = originalN
}

func TestScryptParameters(t *testing.T) {
	keyLen := 32 * 3
	password := []byte("some password")
	salt := RandBytes(keyLen)
	start := time.Now()
	count := 3
	for i := 0; i < count; i++ {
		_, err := scrypt.Key(password, salt, CurrentSCryptParameters.N, CurrentSCryptParameters.R, CurrentSCryptParameters.P, keyLen)
		if err != nil {
			t.Error(err)
		}
	}
	duration := time.Now().Sub(start)
	scryptMs := duration.Milliseconds() / int64(count)
	//fmt.Println("Scrypt parameters taking on average in this CPU:", scryptMs, "ms")
	if scryptMs < 250 {
		t.Errorf("Scrypt should take at least 250ms, it took %vms -- Time to increase its parameters", scryptMs)
	}
}
