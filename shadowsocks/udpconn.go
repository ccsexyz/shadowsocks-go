package shadowsocks

import (
	"fmt"
	"net"
	"sync"
)

// Note: UDPConn will drop any packet that is longer than 1500

type UDPConn struct {
	*net.UDPConn
	rbuf []byte
	wbuf []byte
	c    *Config
}

func NewUDPConn(conn *net.UDPConn, c *Config) *UDPConn {
	return &UDPConn{
		UDPConn: conn,
		c:       c,
		rbuf:    make([]byte, buffersize/2),
		wbuf:    make([]byte, buffersize/2),
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
	enc, err := NewEncrypter(c.c.Method, c.c.Password)
	if err != nil {
		return
	}
	nbytes := copy(c.wbuf, enc.GetIV())
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

type MultiUDPConn struct {
	*net.UDPConn
	rbuf     []byte
	wbuf     []byte
	c        *Config
	sessions map[string]*Config
	lock     sync.Mutex
}

func NewMultiUDPConn(conn *net.UDPConn, c *Config) *MultiUDPConn {
	return &MultiUDPConn{
		UDPConn:  conn,
		c:        c,
		sessions: make(map[string]*Config),
		rbuf:     make([]byte, buffersize/2),
		wbuf:     make([]byte, buffersize/2),
	}
}

func (c *MultiUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if len(b) < 1500 {
		err = fmt.Errorf("the buffer length must be greater than 1500")
		return
	}
	for {
		n, addr, err = c.UDPConn.ReadFrom(c.rbuf)
		if err != nil {
			return
		}
		if n > 1500 {
			continue
		}
		c.lock.Lock()
		v, ok := c.sessions[addr.String()]
		c.lock.Unlock()
		var dec Decrypter
		if !ok {
			host, _, _, _, chs := ParseAddrWithMultipleBackends(c.rbuf[:n], c.c.Backends)
			if len(host) == 0 {
				continue
			}
			c.lock.Lock()
			c.sessions[addr.String()] = chs
			c.lock.Unlock()
			v = chs
			// *(chs.Any.(*int))++
			chs.LogD("udp mode choose", chs.Method, chs.Password)
		}
		dec, err = NewDecrypter(v.Method, v.Password, c.rbuf[:v.Ivlen])
		if err != nil {
			return
		}
		dec.Decrypt(b, c.rbuf[v.Ivlen:n])
		n -= v.Ivlen
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
	enc, err := NewEncrypter(v.Method, v.Password)
	if err != nil {
		return
	}
	nbytes := copy(c.wbuf, enc.GetIV())
	enc.Encrypt(c.wbuf[nbytes:], b)
	nbytes += len(b)
	_, err = c.UDPConn.WriteTo(c.wbuf[:nbytes], addr)
	return
}

func (c *MultiUDPConn) RemoveAddr(addr net.Addr) {
	c.lock.Lock()
	defer c.lock.Unlock()
	delete(c.sessions, addr.String())
}
