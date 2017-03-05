package shadowsocks

import (
	"net"
	"fmt"
	"log"
)

// Note: UDPConn will drop any packet that is longer than 1500

type UDPConn struct {
	net.UDPConn
	rbuf   []byte
	wbuf   []byte
	c      *Config
	Target *ConnTarget
}

func NewUDPConn(conn *net.UDPConn, c *Config) *UDPConn {
	return &UDPConn{
		UDPConn: *conn,
		c: c,
		rbuf: make([]byte, buffersize/2),
		wbuf: make([]byte, buffersize/2),
	}
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if len(b) < 1500 {
		err = fmt.Errorf("the buffer length must be greater than 1500")
		return
	}
	for {
		n, addr, err = c.UDPConn.ReadFrom(c.rbuf)
		if err != nil {
			return
		}
		if n <= c.c.Ivlen || n >= 1500 {
			continue
		}
		var dec Decrypter
		dec, err = NewDecrypter(c.c.Method, c.c.Password, c.rbuf[:c.c.Ivlen])
		if err != nil {
			return
		}
		rbuf := c.rbuf[c.c.Ivlen:n]
		dec.Decrypt(b, rbuf)
		n -= c.c.Ivlen
		return
	}
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	if len(b) > 1500 {
		err = fmt.Errorf("the buffer length must be greater than 1500")
		return
	}
	enc, err := NewEncrypter(c.c.Method, c.c.Password)
	if err != nil {
		return
	}
	nbytes := copy(c.wbuf, enc.GetIV())
	log.Println(nbytes)
	enc.Encrypt(c.wbuf[nbytes:], b)
	nbytes += len(b)
	if addr != nil {
		_, err = c.UDPConn.WriteTo(c.wbuf[:nbytes], addr)
	} else {
		_, err = c.UDPConn.Write(c.wbuf[:nbytes])
	}
	if err == nil {
		n = len(b)
	}
	return
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, nil)
}