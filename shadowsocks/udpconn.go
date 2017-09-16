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
	cfgCtx
	dstCtx
}

func NewUDPConn(conn *net.UDPConn, c *Config) *UDPConn {
	return &UDPConn{
		UDPConn: conn,
		cfgCtx:  cfgCtx{c: c},
	}
}

func (c *UDPConn) GetCfg() *Config {
	return c.c
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if len(b) < 1500 {
		err = fmt.Errorf("the buffer length must be greater than 1500")
		return
	}
	for {
		n, addr, err = c.UDPConn.ReadFrom(b)
		if err != nil {
			return
		}
		if n <= c.c.Ivlen || n >= 1500 {
			continue
		}
		var dec utils.Decrypter
		dec, err = utils.NewDecrypter(c.c.Method, c.c.Password, b[:c.c.Ivlen])
		if err != nil {
			return
		}
		exists := c.c.udpFilterTestAndAdd(dec.GetIV())
		if exists {
			continue
		}
		rbuf := b[c.c.Ivlen:n]
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

func (c *UDPConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	var nbytes int
	for _, buf := range bufs {
		nbytes, err = c.Write(buf)
		n += nbytes
		if err != nil {
			return
		}
	}
	return
}

type MultiUDPConn struct {
	*net.UDPConn
	c        *Config
	sessions sync.Map
}

func NewMultiUDPConn(conn *net.UDPConn, c *Config) *MultiUDPConn {
	return &MultiUDPConn{
		UDPConn: conn,
		c:       c,
	}
}

func (c *MultiUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if len(b) < 1500 {
		err = fmt.Errorf("the buffer length must be greater than 1500")
		return
	}
	b2 := bufPool.Get().([]byte)
	defer bufPool.Put(b2)
	for {
		n, addr, err = c.UDPConn.ReadFrom(b2)
		if err != nil {
			return
		}
		if n > 1500 {
			continue
		}
		v, ok := c.sessions.Load(addr.String())
		var dec utils.Decrypter
		if !ok {
			buf := make([]byte, n)
			sock, data, dec, chs, err := ParseAddrWithMultipleBackends(b2[:n], buf, c.c.Backends)
			if err != nil {
				continue
			}
			exists := chs.udpFilterTestAndAdd(dec.GetIV())
			if exists {
				continue
			}
			c.sessions.Store(addr.String(), chs)
			// *(chs.Any.(*int))++
			chs.LogD("udp mode choose", chs.Method, chs.Password)
			n = copy(b, sock.header)
			n += copy(b[n:], data)
		} else {
			cfg := v.(*Config)
			dec, err = utils.NewDecrypter(cfg.Method, cfg.Password, b2[:cfg.Ivlen])
			if err != nil {
				return
			}
			exists := cfg.udpFilterTestAndAdd(dec.GetIV())
			if exists {
				continue
			}
			dec.Decrypt(b, b2[cfg.Ivlen:n])
			n -= cfg.Ivlen
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
	v, ok := c.sessions.Load(addr.String())
	if !ok {
		return
	}
	cfg := v.(*Config)
	enc, err := utils.NewEncrypter(cfg.Method, cfg.Password)
	if err != nil {
		return
	}
	b2 := make([]byte, cfg.Ivlen+len(b))
	copy(b2, enc.GetIV())
	enc.Encrypt(b2[cfg.Ivlen:], b)
	_, err = c.UDPConn.WriteTo(b2, addr)
	return
}

func (c *MultiUDPConn) RemoveAddr(addr net.Addr) {
	c.sessions.Delete(addr.String())
}
