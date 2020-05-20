package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/cloudflare/circl/dh/sidh"
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
)

type Key struct {
	Type string
	Uuid string
	Pvt  string
	Pub  string
}

type Potp struct {
	Uuid string
	Body string
}

type Unique struct {
	Uid  string
	Cls  string
	Path string
}

type Config struct {
	Keys    []Key
	Potps   []Potp
	Uniques []Unique

	ServerKey           string
	ServerPotp          string
	ClientKey           string
	ClientPotp          string
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
	return cryptoutil.SidhPublicKeyFromString(k.Pub)
}

func (k *Key) GetKemSike() (*sidh.KEM, error) {
	switch k.GetKeyType() {
	case cryptoutil.KeyTypeSidhFp434:
		return sidh.NewSike434(rand.Reader), nil
	case cryptoutil.KeyTypeSidhFp503:
		return sidh.NewSike503(rand.Reader), nil
	case cryptoutil.KeyTypeSidhFp751:
		return sidh.NewSike751(rand.Reader), nil
	default:
		return nil, errors.New("can not create kem for key")
	}
}

func (p *Potp) GetPotpIdAs32Byte() [32]byte {
	b, err := base64.StdEncoding.DecodeString(p.Uuid)
	if err != nil || len(b) != 32 {
		return [32]byte{}
	}
	var res [32]byte
	copy(res[:], b)
	return res
}

func (p *Potp) GetBodyAsArray() []byte {
	b, err := base64.StdEncoding.DecodeString(p.Body)
	if err != nil {
		return make([]byte, 0)
	}
	return b
}
func (p *Potp) GetSize() uint64 {
	return uint64(len(p.GetBodyAsArray()))
}

// the following does not implements file based OTPs
func (p *Potp) PickOTP(size int) (otp []byte, offset uint64) {
	wholeOtp := p.GetBodyAsArray()
	ofs, err := rand.Int(rand.Reader, big.NewInt(int64(len(wholeOtp))-int64(size))) // -size for the sake of simplicity
	if err != nil {
		panic(err)
	}
	return wholeOtp[ofs.Uint64() : ofs.Uint64()+uint64(size)], ofs.Uint64()
}

func (p *Potp) ReadOTP(size int, offset uint64) ([]byte, error) {
	wholeOtp := p.GetBodyAsArray()
	if len(wholeOtp) < int(offset) {
		//This is important: the offset can be any value, so the length of the potp is not disclosed indirectly
		//i.e. further improvements to the protocol has to send values greater than the potp's size,
		//so an eavesdropper can't imply its size.
		//FIX: fix int vs uint64 but then file based potp are implemented, small/json-config ones will be less than 2gb
		offset = uint64(int(offset) % len(wholeOtp))
	}
	if len(wholeOtp) < int(offset)+size {
		// for the sake of simplicity, so it does not have to pick two parts
		offset = 0
	}
	res := make([]byte, size)
	copy(res, wholeOtp[int(offset):int(offset)+size])
	return res, nil
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

func (c *Config) GetPotpByID(potpId string) (*Potp, error) {
	// FIXME: needs locking, not lineal search (might not be necessary ...)
	for _, p := range c.Potps {
		if potpId == p.Uuid {
			return &p, nil
		}
	}
	return nil, errors.Errorf("PotpId: %v not found.", potpId)
}

func (c *Config) CreateAndAddInPlacePotp(size int) (*Potp, error) {
	b := cryptoutil.RandBytes(size)
	uuid := base64.StdEncoding.EncodeToString(cryptoutil.QuickSha256(b))
	potp := Potp{
		Uuid: uuid,
		Body: base64.StdEncoding.EncodeToString(b),
	}
	c.Potps = append(c.Potps, potp)
	return &potp, nil
}

func NewEmpty() *Config {
	return &Config{
		Keys:                make([]Key, 0),
		Potps:               make([]Potp, 0),
		Uniques:             make([]Unique, 0),
		ServerKey:           "",
		ServerPotp:          "",
		PuzzleDifficulty:    16, // as 2020, roughly 100ms on Ryzen 3800X using vanilla  impl
		RequireTripleAES256: false,
	}
}
