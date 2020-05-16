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
