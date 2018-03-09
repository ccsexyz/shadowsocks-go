package ss

import (
	"io"
	"net"

	"github.com/ccsexyz/utils"
)

// Conn interface is base interface of all connection of shadowsocks
type Conn interface {
	net.Conn

	ReadBuffer([]byte) ([]byte, error)
	WriteBuffers([][]byte) error
}

// baseConn implements ReadBuffer and WriteBuffers method
type baseConn struct {
	net.Conn
}

func (conn *baseConn) ReadBuffer(b []byte) ([]byte, error) {
	n, err := conn.Conn.Read(b)
	return b[:n], err
}

func (conn *baseConn) WriteBuffers(bufs [][]byte) error {
	buffers := net.Buffers(bufs)
	var nbytesToWrite int64
	for _, buf := range bufs {
		nbytesToWrite += int64(len(buf))
	}
	n, err := buffers.WriteTo(conn.Conn)
	if err != nil {
		return err
	}
	if n != nbytesToWrite {
		return io.ErrShortWrite
	}
	return nil
}

// NewConnFromNetConn creates baseConn from net.Conn
func NewConnFromNetConn(conn net.Conn) Conn {
	return &baseConn{Conn: conn}
}

type DecrypterMaker interface {
	Make(iv []byte) (utils.Decrypter, error)
	Ivlen() int
}

type EncrypterMaker interface {
	Make() (utils.Encrypter, error)
}

type UtilsDecrypterMaker struct {
	method   string
	password string
	ivlen    int
}

func NewUtilsDecrypterMaker(method, password string) DecrypterMaker {
	return &UtilsDecrypterMaker{
		method:   method,
		password: password,
		ivlen:    utils.GetIvLen(method),
	}
}

func (m *UtilsDecrypterMaker) Make(iv []byte) (utils.Decrypter, error) {
	if len(iv) < m.ivlen {
		return nil, io.ErrShortBuffer
	}
	return utils.NewDecrypter(m.method, m.password, iv)
}

func (m *UtilsDecrypterMaker) Ivlen() int {
	return m.ivlen
}

type UtilsEncrypterMaker struct {
	method   string
	password string
}

func NewUtilsEncrypterMaker(method, password string) EncrypterMaker {
	return &UtilsEncrypterMaker{
		method:   method,
		password: password,
	}
}

func (m *UtilsEncrypterMaker) Make() (utils.Encrypter, error) {
	return utils.NewEncrypter(m.method, m.password)
}

type ShadowSocksConn struct {
	Conn
	enc      utils.Encrypter
	dec      utils.Decrypter
	encMaker EncrypterMaker
	decMaker DecrypterMaker
}

func NewShadowSocksConn(conn Conn, encMaker EncrypterMaker, decMaker DecrypterMaker) Conn {
	return &ShadowSocksConn{
		Conn:     conn,
		encMaker: encMaker,
		decMaker: decMaker,
	}
}

func (c *ShadowSocksConn) ReadBuffer(b []byte) ([]byte, error) {
	ivlen := c.decMaker.Ivlen()
	if len(b) < ivlen {
		return nil, io.ErrShortBuffer
	}
	if c.dec == nil {
		err := ReadFull(c.Conn, b[:ivlen])
		if err != nil {
			return nil, err
		}
		c.dec, err = c.decMaker.Make(b[:ivlen])
		if err != nil {
			return nil, err
		}
	}
	b, err := c.Conn.ReadBuffer(b)
	if err != nil {
		return nil, err
	}
	c.dec.Decrypt(b, b)
	return b, nil
}

func (c *ShadowSocksConn) WriteBuffers(bufs [][]byte) error {
	var enc utils.Encrypter
	var err error
	if c.enc != nil {
		enc = c.enc
	} else {
		enc, err = c.encMaker.Make()
		if err != nil {
			return err
		}
	}
	for _, buf := range bufs {
		enc.Encrypt(buf, buf)
	}
	if c.enc == nil {
		c.enc = enc
		bufs = append([][]byte{enc.GetIV()}, bufs...)
	}
	return c.Conn.WriteBuffers(bufs)
}

type RemainConn struct {
	Conn

	spinRead   Spin
	spinWrite  Spin
	bufToRead  []byte
	bufToWrite []byte
}

func NewRemainConn(conn Conn, r, w []byte) Conn {
	remainConn := &RemainConn{Conn: conn}
	if len(r) > 0 {
		remainConn.bufToRead = utils.CopyBuffer(r)
	}
	if len(w) > 0 {
		remainConn.bufToWrite = utils.CopyBuffer(w)
	}
	return remainConn
}

// func (c *RemainConn) Close() error {
// 	var r, w []byte
// 	c.spinRead.Run(func() {
// 		if len(c.bufToRead) > 0 {
// 			r, c.bufToRead = c.bufToRead, nil
// 		}
// 	})
// 	c.spinWrite.Run(func() {
// 		if len(c.bufToWrite) > 0 {
// 			w, c.bufToWrite = c.bufToWrite, nil
// 		}
// 	})
// 	return nil
// }

func (c *RemainConn) ReadBuffer(b []byte) ([]byte, error) {
	if len(c.bufToRead) != 0 {
		b, c.bufToRead = c.bufToRead, nil
		return b, nil
	}
	return c.Conn.ReadBuffer(b)
}

func (c *RemainConn) WriteBuffers(bufs [][]byte) error {
	if len(c.bufToWrite) != 0 {
		bufs = append([][]byte{c.bufToWrite}, bufs...)
		c.bufToWrite = nil
	}
	return c.Conn.WriteBuffers(bufs)
}
