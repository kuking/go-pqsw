package wire

import (
	"github.com/google/logger"
	"net"
)

func terminateHandshakeOnError(conn net.Conn, err error, explanation string) bool {
	if err == nil {
		return false
	}
	logger.Infof("remote: '%v' terminated with error: '%v', while: '%v'", conn.RemoteAddr(), err, explanation)
	err2 := conn.Close()
	if err2 != nil {
		logger.Infof("could not close connection %v", conn)
	}
	return true
}

func BuildSecureWire(keysBytes []byte, conn net.Conn) (wire *SecureWire, err error) {
	ofs := 0
	oneKeySize := 32
	oneNonceSize := 12
	if len(keysBytes) == oneKeySize+oneNonceSize { // SimpleAES256
		return NewSecureWireAES256CGM(keysBytes[ofs:ofs+oneKeySize], keysBytes[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], conn)
	}
	w2, err := NewSecureWireAES256CGM(keysBytes[ofs:ofs+oneKeySize], keysBytes[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], conn)
	if err != nil {
		return
	}
	ofs = ofs + oneKeySize + oneNonceSize
	w1, err := NewSecureWireAES256CGM(keysBytes[ofs:ofs+oneKeySize], keysBytes[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], w2)
	if err != nil {
		return
	}
	ofs = ofs + oneKeySize + oneNonceSize
	return NewSecureWireAES256CGM(keysBytes[ofs:ofs+oneKeySize], keysBytes[ofs+oneKeySize:ofs+oneKeySize+oneNonceSize], w1)
}
