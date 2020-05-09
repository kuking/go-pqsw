package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/pkg/errors"
	"io/ioutil"
)

type Key struct {
	Type string
	Uuid string
	Pvt  string
	Pub  string
}

type Psk struct {
	Uid  string
	Path string
	Body string
	Hash string
}

type Unique struct {
	Uid  string
	Cls  string
	Path string
}

type Config struct {
	Keys    []Key
	Psks    []Psk
	Uniques []Unique

	ServerKey           string
	ServerPsk           string
	PuzzleDifficulty    int
	RequireTripleAES256 bool
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

func (k *Key) GetKeyType() cryptoutil.KeyType {
	for kt, kts := range cryptoutil.KeyTypeAsString {
		if k.Type == kts {
			return kt
		}
	}
	return cryptoutil.KeyTypeUnknown
}

func (k *Key) GetSidhPrivateKey() *sidh.PrivateKey {
	return cryptoutil.SidhPrivateKeyFromString(k.Pvt)
}

func (k *Key) GetSidhPublicKey() *sidh.PublicKey {
	return cryptoutil.SidhPublicKeyFromString(k.Pvt)
}

func (k *Key) GetKemSike() (*sidh.KEM, error) {
	switch k.GetKeyType() {
	case cryptoutil.KeyTypeSidhFp503:
		return sidh.NewSike503(rand.Reader), nil
	case cryptoutil.KeyTypeSidhFp751:
		return sidh.NewSike751(rand.Reader), nil
	default:
		return nil, errors.New("can not create kem for key")
	}
}

func (c *Config) CreateAndAddKey(keyType cryptoutil.KeyType) (*Key, error) {

	var pvt *sidh.PrivateKey
	var pub *sidh.PublicKey
	pvt, pub, err := cryptoutil.SidhNewPair(keyType)
	if err != nil {
		return nil, err
	}

	keyId := cryptoutil.SidhKeyId(pub)
	key := Key{
		Type: cryptoutil.KeyTypeAsString[keyType],
		Uuid: keyId,
		Pvt:  cryptoutil.SidhPrivateKeyAsString(pvt),
		Pub:  cryptoutil.SidhPublicKeyAsString(pub),
	}
	c.Keys = append(c.Keys, key)
	return &key, nil
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

func (c *Config) CreateInPlacePsk(size int) (*Psk, error) {
	b := cryptoutil.RandBytes(size)
	uid := base64.StdEncoding.EncodeToString(cryptoutil.QuickSha256(b))
	psk := Psk{
		Uid:  uid,
		Path: "",
		Body: base64.StdEncoding.EncodeToString(b),
		Hash: uid,
	}
	c.Psks = append(c.Psks, psk)
	return &psk, nil
}

func NewEmpty() *Config {
	return &Config{
		Keys:                make([]Key, 0),
		Psks:                make([]Psk, 0),
		Uniques:             make([]Unique, 0),
		ServerKey:           "",
		ServerPsk:           "",
		PuzzleDifficulty:    16, // as 2020, roughly 100ms on Ryzen 3800X using vanilla  impl
		RequireTripleAES256: false,
	}
}
