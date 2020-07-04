package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"github.com/pkg/errors"
	"io"
	"net"
	"time"
)

const NetworkBufferSize = 65 * 1024

type PayLoadSize struct {
	Size uint32
}

func (p PayLoadSize) asInt() int {
	return int(p.Size)
}

type SecureWire struct {
	underlying  net.Conn
	aead        cipher.AEAD
	nonce       []byte
	readBuffer  []byte
	writeBuffer []byte
	sendSeqNo   uint32
	recvSeqNo   uint32
	localKeyId  [32]byte
	remoteKeyId [32]byte
}

func NewSecureWireAES256CGM(key []byte, nonce []byte, conn net.Conn, localKeyId, remoteKeyId [32]byte) (sw *SecureWire, err error) {
	if len(key) != 32 {
		return nil, errors.Errorf("key must be 256 bits (32 bytes), but provided %v bytes.", len(key))
	}
	if len(nonce) != 12 {
		return nil, errors.Errorf("nonce must be 96 bits (12 bytes), but provided %v bytes.", len(nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecureWire{
		underlying:  conn,
		aead:        aesgcm,
		nonce:       nonce,
		readBuffer:  make([]byte, NetworkBufferSize),
		writeBuffer: make([]byte, NetworkBufferSize),
		sendSeqNo:   0,
		recvSeqNo:   0,
		localKeyId:  localKeyId,
		remoteKeyId: remoteKeyId,
	}, nil
}

func (s *SecureWire) nonceForSequence(seq uint32) (nonce []byte) {
	nonce = make([]byte, len(s.nonce))
	copy(nonce, s.nonce)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, seq)
	nIdx := len(nonce) - len(b)
	for i := 0; i < len(b); i++ {
		nonce[nIdx+i] = nonce[nIdx+i] ^ b[i]
	}
	return nonce
}

func (s *SecureWire) Read(b []byte) (n int, err error) {
	s.recvSeqNo++
	var payloadSize PayLoadSize
	err = binary.Read(s.underlying, binary.LittleEndian, &payloadSize)
	if err != nil {
		return n, errors.Wrap(err, "secure_wire: read: failed to read payload")
	}
	if payloadSize.asInt() > len(s.readBuffer) {
		_ = s.Close()
		return 0, errors.Errorf("secure_wire: read: payload size too big, length: %v", payloadSize.asInt())
	}
	n, err = io.ReadFull(s.underlying, s.readBuffer[0:payloadSize.asInt()])
	if err != nil || n != int(payloadSize.Size) {
		return 0, errors.Wrapf(err, "secure_wire: read: failed to read %v bytes of payload", payloadSize.asInt())

	}
	slice, err := s.aead.Open(s.readBuffer[:0], s.nonceForSequence(s.recvSeqNo), s.readBuffer[0:n], nil)
	if err != nil {
		_ = s.Close()
		return 0, errors.Wrap(err, "secure_wire: read: closing wire because seal failed to open")
	}
	copy(b, slice)
	return len(slice), err
}

func (s *SecureWire) Write(b []byte) (n int, err error) {
	s.sendSeqNo++
	sealed := s.aead.Seal(s.writeBuffer[:0], s.nonceForSequence(s.sendSeqNo), b, nil)
	var payloadSize = PayLoadSize{uint32(len(sealed))}
	err = binary.Write(s.underlying, binary.LittleEndian, &payloadSize)
	if err != nil {
		return n, errors.Wrap(err, "secure_wire: write: failed to write payload size")
	}
	m, err := s.underlying.Write(sealed) // or write slice returned by seal?
	if m == len(sealed) && err == nil {
		return len(b), err // return original size
	} else {
		return 0, errors.Wrapf(err, "secure_wire: write: failed to write ciphertext (wrote %v, expected %v)",
			m, len(sealed))
	}
}

func (s *SecureWire) Close() error {
	return s.underlying.Close()
}

func (s *SecureWire) LocalAddr() net.Addr {
	return s.underlying.LocalAddr()
}

func (s *SecureWire) RemoteAddr() net.Addr {
	return s.underlying.RemoteAddr()
}

func (s *SecureWire) SetDeadline(t time.Time) error {
	return s.underlying.SetDeadline(t)
}

func (s *SecureWire) SetReadDeadline(t time.Time) error {
	return s.underlying.SetReadDeadline(t)
}

func (s *SecureWire) SetWriteDeadline(t time.Time) error {
	return s.underlying.SetWriteDeadline(t)
}

func (s *SecureWire) LocalKeyId() [32]byte {
	return s.localKeyId
}

func (s *SecureWire) RemoteKeyId() [32]byte {
	return s.remoteKeyId
}
