package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/kuking/go-pqsw/cryptoutil"
	"github.com/kuking/go-pqsw/misc"
	"github.com/pkg/errors"
	"io/ioutil"
	"math/big"
	"strconv"
)

type Key struct {
	Type string
	CN   string
	Uuid string
	Pvt  string
	Pub  string
}

type Potp struct {
	Uuid string
	CN   string
	Body string
}

type Config struct {
	Keys                []Key
	Potps               []Potp
	PreferredKeyCN      string
	PreferredPotpCN     string
	PuzzleDifficulty    int
	RequireTripleAES256 bool
	passwordInDisk      string
}

func (k *Key) IdAs32Byte() [32]byte {
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

func (k *Key) PvtBytes() (pvt []byte) {
	pvt, _ = base64.StdEncoding.DecodeString(k.Pvt)
	return
}

func (k *Key) PubBytes() (pub []byte) {
	pub, _ = base64.StdEncoding.DecodeString(k.Pub)
	return
}

func (p *Potp) IdAs32Byte() [32]byte {
	b, err := base64.StdEncoding.DecodeString(p.Uuid)
	if err != nil || len(b) != 32 {
		return [32]byte{}
	}
	var res [32]byte
	copy(res[:], b)
	return res
}

func (p *Potp) BodyBytes() []byte {
	b, err := base64.StdEncoding.DecodeString(p.Body)
	if err != nil {
		return make([]byte, 0)
	}
	return b
}
func (p *Potp) GetSize() uint64 {
	return uint64(len(p.BodyBytes()))
}

// the following does not implements file based OTPs
func (p *Potp) PickOTP(size int) (otp []byte, offset uint64) {
	wholeOtp := p.BodyBytes()
	ofs, err := rand.Int(rand.Reader, big.NewInt(int64(len(wholeOtp))-int64(size))) // -size for the sake of simplicity
	if err != nil {
		panic(err)
	}
	return wholeOtp[ofs.Uint64() : ofs.Uint64()+uint64(size)], ofs.Uint64()
}

func (p *Potp) ReadOTP(size int, offset uint64) ([]byte, error) {
	wholeOtp := p.BodyBytes()
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

func (c *Config) NextSequentialKeyCN() int64 {
	highest := int64(0)
	for _, key := range c.Keys {
		n, err := strconv.ParseInt(key.CN, 10, 32)
		if err != nil {
			if highest < n {
				highest = n
			}
		}
	}
	return highest + 1
}

func (c *Config) NextSequentialPotpCN() int64 {
	highest := int64(0)
	for _, potp := range c.Potps {
		n, err := strconv.ParseInt(potp.CN, 10, 32)
		if err != nil {
			if highest < n {
				highest = n
			}
		}
	}
	return highest + 1
}

func (c *Config) CreateAndAddKey(keyType cryptoutil.KeyType, cn string) (*Key, error) {

	var pvt []byte
	var pub []byte

	pvt, pub, err := cryptoutil.GenKey(keyType)
	if err != nil {
		return nil, err
	}

	keyId := cryptoutil.KeyId(pub)
	key := Key{
		Type: cryptoutil.KeyTypeAsString[keyType],
		CN:   cn,
		Uuid: keyId,
		Pvt:  cryptoutil.PrivateKeyAsString(pvt),
		Pub:  cryptoutil.PublicKeyAsString(pub),
	}
	c.Keys = append(c.Keys, key)
	return &key, nil
}

// It will ask for a password, if required
func LoadFromInteractive(file string) (cfg *Config, err error) {
	cfg, err = LoadFrom(file, "")
	if err == nil {
		return
	}
	password, err := misc.GetPassword()
	if err != nil {
		return
	}
	return LoadFrom(file, password)
}

// Empty password implies no encryption
func LoadFrom(file string, password string) (cfg *Config, err error) {
	cfg = NewEmpty()
	bytes, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}
	if password != "" {
		bytes, err = cryptoutil.SimpleSuperTripleDecrypt(bytes, password)
		if err != nil {
			return
		}
	}
	err = json.Unmarshal(bytes, &cfg)
	cfg.passwordInDisk = password
	return
}

func (c *Config) SaveTo(file string) (err error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return
	}
	if c.passwordInDisk != "" {
		b, err = cryptoutil.SimpleSuperTripleEncrypt(b, c.passwordInDisk)
		if err != nil {
			return
		}
	}
	err = ioutil.WriteFile(file, b, 0o600)
	return
}

func (c *Config) SetDiskEncryptionPassword(password string) {
	c.passwordInDisk = password
}

func (c *Config) HasDiskEncryptionPassword() bool {
	return c.passwordInDisk != ""
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
	for _, k := range c.Keys {
		if keyId == k.Uuid {
			return &k, nil
		}
	}
	return nil, errors.Errorf("KeyId: %v not found.", keyId)
}

func (c *Config) GetKeyByCN(cn string) (*Key, error) {
	for _, k := range c.Keys {
		if cn == k.CN {
			return &k, nil
		}
	}
	return nil, errors.Errorf("Key  CN: %v not found.", cn)
}

func (c *Config) GetPotpByID(potpId string) (*Potp, error) {
	for _, p := range c.Potps {
		if potpId == p.Uuid {
			return &p, nil
		}
	}
	return nil, errors.Errorf("PotpId: %v not found.", potpId)
}

func (c *Config) GetPotpByCN(cn string) (*Potp, error) {
	for _, p := range c.Potps {
		if cn == p.CN {
			return &p, nil
		}
	}
	return nil, errors.Errorf("Potp CN: %v not found.", cn)
}

func (c *Config) DeletePotpByUUID(uuid string) bool {
	delIdx := -1
	for idx, potp := range c.Potps {
		if potp.Uuid == uuid {
			delIdx = idx
		}
	}
	if delIdx == -1 {
		return false
	}
	c.Potps = append(c.Potps[:delIdx], c.Potps[delIdx+1:]...)
	return true
}

func (c *Config) CreateAndAddInPlacePotp(size int, cn string) (*Potp, error) {
	b := cryptoutil.RandBytes(size)
	uuid := base64.StdEncoding.EncodeToString(cryptoutil.QuickSha256(b))
	potp := Potp{
		Uuid: uuid,
		CN:   cn,
		Body: base64.StdEncoding.EncodeToString(b),
	}
	c.Potps = append(c.Potps, potp)
	return &potp, nil
}

func NewEmpty() *Config {
	return &Config{
		Keys:                make([]Key, 0),
		Potps:               make([]Potp, 0),
		PreferredKeyCN:      "",
		PreferredPotpCN:     "",
		PuzzleDifficulty:    18, // as 2020, roughly 150-250ms on Ryzen 3800X using vanilla impl
		RequireTripleAES256: false,
	}
}
