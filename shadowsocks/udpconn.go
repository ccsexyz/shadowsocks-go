package shadowsocks

import (
	"fmt"
	"net"
	"sync"

	"github.com/ccsexyz/utils"
)

// Note: UDPConn will drop any packet that is longer than 1500

type UDPConn struct {
	*net.UDPConn
	c *Config
}

func NewUDPConn(conn *net.UDPConn, c *Config) *UDPConn {
	return &UDPConn{
		UDPConn: conn,
		c:       c,
	}
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if len(b) < 1500 {
		err = fmt.Errorf("the buffer length must be greater than 1500")
		return
	}
	b2 := make([]byte, buffersize)
	for {
		n, addr, err = c.UDPConn.ReadFrom(b2)
		if err != nil {
			return
		}
		if n <= c.c.Ivlen || n >= 1500 {
			continue
		}
		var dec utils.Decrypter
		dec, err = utils.NewDecrypter(c.c.Method, c.c.Password, b2[:c.c.Ivlen])
		if err != nil {
			return
		}
		rbuf := b2[c.c.Ivlen:n]
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
	enc, err := utils.NewEncrypter(c.c.Method, c.c.Password)
	if err != nil {
		return
	}
	b2 := make([]byte, c.c.Ivlen+len(b))
	copy(b2, enc.GetIV())
	enc.Encrypt(b2[c.c.Ivlen:], b)
	if addr != nil {
		_, err = c.UDPConn.WriteTo(b2, addr)
	} else {
		_, err = c.UDPConn.Write(b2)
	}
	if err == nil {
		n = len(b)
	}
	return
}

func (c *UDPConn) Write(b []byte) (n int, err error) {
	return c.WriteTo(b, nil)
}

type MultiUDPConn struct {
	*net.UDPConn
	c        *Config
	sessions map[string]*Config
	lock     sync.Mutex
}

func NewMultiUDPConn(conn *net.UDPConn, c *Config) *MultiUDPConn {
	return &MultiUDPConn{
		UDPConn:  conn,
		c:        c,
		sessions: make(map[string]*Config),
	}
}

func (c *MultiUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if len(b) < 1500 {
		err = fmt.Errorf("the buffer length must be greater than 1500")
		return
	}
	b2 := make([]byte, buffersize)
	for {
		n, addr, err = c.UDPConn.ReadFrom(b2)
		if err != nil {
			return
		}
		if n > 1500 {
			continue
		}
		c.lock.Lock()
		v, ok := c.sessions[addr.String()]
		c.lock.Unlock()
		var dec utils.Decrypter
		if !ok {
			buf := make([]byte, n)
			sock, data, _, chs, err := ParseAddrWithMultipleBackends(b2[:n], buf, c.c.Backends)
			if err != nil {
				continue
			}
			c.lock.Lock()
			c.sessions[addr.String()] = chs
			c.lock.Unlock()
			// *(chs.Any.(*int))++
			chs.LogD("udp mode choose", chs.Method, chs.Password)
			n = copy(b, []byte(sock))
			n += copy(b[n:], data)
		} else {
			dec, err = utils.NewDecrypter(v.Method, v.Password, b2[:v.Ivlen])
			if err != nil {
				return
			}
			dec.Decrypt(b, b2[v.Ivlen:n])
			n -= v.Ivlen
		}
		return
	}
}

func (c *MultiUDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	defer func() {
		if err == nil {
			n = len(b)
		}
	}()
	c.lock.Lock()
	v, ok := c.sessions[addr.String()]
	c.lock.Unlock()
	if !ok {
		return
	}
	enc, err := utils.NewEncrypter(v.Method, v.Password)
	if err != nil {
		return
	}
	b2 := make([]byte, v.Ivlen+len(b))
	copy(b2, enc.GetIV())
	enc.Encrypt(b2[v.Ivlen:], b)
	_, err = c.UDPConn.WriteTo(b2, addr)
	return
}

func (c *MultiUDPConn) RemoveAddr(addr net.Addr) {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.sessions, addr.String())
}
