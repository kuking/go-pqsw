package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cloudflare/circl/dh/sidh"
	"io/ioutil"
)

type KeyType uint8

const (
	KeyTypeSidhFp503 KeyType = 1
	KeyTypeSidhFp751 KeyType = 2
)

var KeyTypeAsString = map[KeyType]string{
	KeyTypeSidhFp503: "SIDH_FP503",
	KeyTypeSidhFp751: "SIDH_FP751",
}

type Key struct {
	Type string
	Uid  string
	Pvt  string
	Pub  string
}

type Otp struct {
	Uid  string
	Path string
	Hash string
}

type Unique struct {
	Uid  string
	Cls  string
	Path string
}

type Config struct {
	Keys    []Key
	Otps    []Otp
	Uniques []Unique
}

func (c *Config) CreateAndAddKey(keyType KeyType) error {

	var pvt *sidh.PrivateKey
	var pub *sidh.PublicKey

	if keyType == KeyTypeSidhFp503 {
		pvt = sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSike)
		pub = sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)
	} else if keyType == KeyTypeSidhFp751 {
		pvt = sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
		pub = sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	} else {
		return errors.New(fmt.Sprintf("I do not know how to create a key type %d.", keyType))
	}
	err := pvt.Generate(rand.Reader)
	if err != nil {
		return err
	}
	pvt.GeneratePublicKey(pub)

	pvtBytes := bytesForSidhPrivateKey(pvt)
	pubBytes := bytesForSidhPublicKey(pub)

	key := Key{
		Type: KeyTypeAsString[keyType],
		Uid:  base64.StdEncoding.EncodeToString(doSha256(pubBytes)),
		Pvt:  base64.StdEncoding.EncodeToString(pvtBytes),
		Pub:  base64.StdEncoding.EncodeToString(pubBytes),
	}
	c.Keys = append(c.Keys, key)
	return nil
}

func bytesForSidhPrivateKey(pvt *sidh.PrivateKey) []byte {
	b := make([]byte, pvt.Size())
	pvt.Export(b)
	return b
}

func bytesForSidhPublicKey(pvt *sidh.PublicKey) []byte {
	b := make([]byte, pvt.Size())
	pvt.Export(b)
	return b
}

func doSha256(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func LoadFrom(file string) (*Config, error) {
	config := NewEmpty()
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(bytes, &config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (c *Config) SaveTo(file string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(file, b, 0o600)
	if err != nil {
		return err
	}
	return nil
}

func NewEmpty() *Config {
	return &Config{
		Keys:    make([]Key, 0),
		Otps:    make([]Otp, 0),
		Uniques: make([]Unique, 0),
	}
}
