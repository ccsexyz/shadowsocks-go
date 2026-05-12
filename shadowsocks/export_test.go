package ss

import (
	"io"
	"net"
)

// --- test codec for CryptoConn ---

type testCodec struct{}

func (c *testCodec) ReadFrame(r io.Reader) ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *testCodec) WriteFrame(w io.Writer, plaintext []byte) error {
	_, err := w.Write(plaintext)
	return err
}

func (c *testCodec) Overhead() int { return 0 }
func (c *testCodec) Close() error  { return nil }

// --- test helpers to construct conn wrapper chains ---

func NewBaseConnForTest(conn net.Conn) *BaseConn {
	return newBaseConn(conn, nil)
}

func NewCryptoConnForTest(conn Conn) *CryptoConn {
	return &CryptoConn{Conn: conn, codec: &testCodec{}}
}

func NewRemainConnForTest(conn Conn, remain []byte) *RemainConn {
	return &RemainConn{Conn: conn, remain: remain}
}
