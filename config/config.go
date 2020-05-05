package config

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/kuking/go-pqsw/wire/msg"
	"github.com/pkg/errors"
	"io/ioutil"
)

type KeyType uint8

const (
	KeyTypeInvalid   KeyType = 0
	KeyTypeSidhFp503 KeyType = 1
	KeyTypeSidhFp751 KeyType = 2
)

var KeyTypeAsString = map[KeyType]string{
	KeyTypeSidhFp503: "SIDH_FP503",
	KeyTypeSidhFp751: "SIDH_FP751",
}

type Key struct {
	Type string
	Uuid string
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
	Keys                      []Key
	Otps                      []Otp
	Uniques                   []Unique
	ClientProvingKeyDerivAlgo uint16 // not wired yet
	ClientProvingKeyIters     uint32 // not wired yet
}

func (k *Key) GetKeyIdAs32Byte() [32]byte {
	b, err := base64.StdEncoding.DecodeString(k.Uuid)
	if err != nil || len(b) != 32 {
		return [32]byte{}
	}
	var res [32]byte
	copy(res[:], b)
	return res
}

func (c *Config) CreateAndAddKey(keyType KeyType) (*string, error) {

	var pvt *sidh.PrivateKey
	var pub *sidh.PublicKey

	if keyType == KeyTypeSidhFp503 {
		pvt = sidh.NewPrivateKey(sidh.Fp503, sidh.KeyVariantSike)
		pub = sidh.NewPublicKey(sidh.Fp503, sidh.KeyVariantSike)
	} else if keyType == KeyTypeSidhFp751 {
		pvt = sidh.NewPrivateKey(sidh.Fp751, sidh.KeyVariantSike)
		pub = sidh.NewPublicKey(sidh.Fp751, sidh.KeyVariantSike)
	} else {
		return nil, errors.Errorf("I do not know how to create a key type %d.", keyType)
	}
	err := pvt.Generate(rand.Reader)
	if err != nil {
		return nil, err
	}
	pvt.GeneratePublicKey(pub)

	pvtBytes := bytesForSidhPrivateKey(pvt)
	pubBytes := bytesForSidhPublicKey(pub)

	keyId := base64.StdEncoding.EncodeToString(doSha256(pubBytes))
	key := Key{
		Type: KeyTypeAsString[keyType],
		Uuid: keyId,
		Pvt:  base64.StdEncoding.EncodeToString(pvtBytes),
		Pub:  base64.StdEncoding.EncodeToString(pubBytes),
	}
	c.Keys = append(c.Keys, key)
	return &keyId, nil
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

func (c *Config) DeleteKeyByUUID(uuid string) bool {
	delIdx := -1
	for idx, key := range c.Keys {
		if key.Uuid == uuid {
			delIdx = idx
		}
	}
	if delIdx == -1 {
		return false
	}
	c.Keys = append(c.Keys[:delIdx], c.Keys[delIdx+1:]...)
	return true
}

func (c *Config) ContainsKeyById(keyId string) bool {
	_, err := c.GetKeyByID(keyId)
	return err == nil
}

func (c *Config) GetKeyByID(keyId string) (*Key, error) {
	// FIXME: needs locking, not lineal search (might not be necessary ...)
	for _, k := range c.Keys {
		if keyId == k.Uuid {
			return &k, nil
		}
	}
	return nil, errors.Errorf("KeyId: %v not found.", keyId)
}

func NewEmpty() *Config {
	return &Config{
		Keys:                      make([]Key, 0),
		Otps:                      make([]Otp, 0),
		Uniques:                   make([]Unique, 0),
		ClientProvingKeyDerivAlgo: msg.PuzzleSHA512LZ,
		ClientProvingKeyIters:     msg.SHA512LZParam,
	}
}
