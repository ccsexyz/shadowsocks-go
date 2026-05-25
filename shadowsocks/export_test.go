package ss

import (
	"net"
)

// --- test helpers to construct conn wrapper chains ---

func NewBaseConnForTest(conn net.Conn) *BaseConn {
	return newBaseConn(conn, nil)
}

func NewCryptoConnStreamForTest(conn Conn) *cryptoConnStream {
	return newCryptoConnStream(conn, nil, nil)
}

func NewRemainConnForTest(conn Conn, remain []byte) *RemainConn {
	return &RemainConn{Conn: conn, remain: remain}
}
