package ss

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/redir"
	"github.com/ccsexyz/utils"
)

// Note: UDPConn will drop any packet that is longer than 1500

type UDPConn struct {
	net.PacketConn
	net.Conn
	cfgCtx
	dstCtx
}

func NewUDPConn1(conn utils.UDPConn, c *Config) *UDPConn {
	return &UDPConn{
		PacketConn: conn,
		Conn:       conn,
		cfgCtx:     cfgCtx{c: c},
	}
}

func NewUDPConn2(conn net.Conn, c *Config) *UDPConn {
	return &UDPConn{
		Conn:   conn,
		cfgCtx: cfgCtx{c: c},
	}
}

func NewUDPConn3(conn net.PacketConn, c *Config) *UDPConn {
	return &UDPConn{
		PacketConn: conn,
		cfgCtx:     cfgCtx{c: c},
	}
}

func (c *UDPConn) LocalAddr() net.Addr {
	if c.Conn != nil {
		return c.Conn.LocalAddr()
	}
	return c.PacketConn.LocalAddr()
}

func (c *UDPConn) Close() error {
	if c.Conn != nil {
		c.Conn.Close()
	}
	if c.PacketConn != nil {
		c.PacketConn.Close()
	}
	return nil
}

func (c *UDPConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	if c.PacketConn != nil {
		return c.PacketConn.SetDeadline(t)
	}
	return c.Conn.SetDeadline(t)
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	if c.PacketConn != nil {
		return c.PacketConn.SetReadDeadline(t)
	}
	return c.Conn.SetReadDeadline(t)
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	if c.PacketConn != nil {
		return c.PacketConn.SetWriteDeadline(t)
	}
	return c.Conn.SetWriteDeadline(t)
}

func (c *UDPConn) GetCfg() *Config {
	return c.c
}

func (c *UDPConn) fakeReadFrom(b []byte) (int, net.Addr, error) {
	n, err := c.Conn.Read(b)
	return n, nil, err
}

func (c *UDPConn) readImpl(b []byte, readfrom func([]byte) (int, net.Addr, error)) (int, net.Addr, error) {
	for {
		n, addr, err := readfrom(b)
		if err != nil {
			return 0, addr, err
		}
		if n < c.c.Ivlen {
			continue
		}
		dec, err := utils.NewDecrypter(c.c.Method, c.c.Password, b[:c.c.Ivlen])
		if err != nil {
			return 0, addr, err
		}
		exists := c.c.udpFilterTestAndAdd(dec.GetIV())
		if exists {
			continue
		}
		rbuf := b[c.c.Ivlen:n]
		dec.Decrypt(b, rbuf)
		return len(rbuf), addr, nil
	}
}

func (c *UDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	return c.readImpl(b, c.PacketConn.ReadFrom)
}

func (c *UDPConn) Read(b []byte) (n int, err error) {
	n, _, err = c.readImpl(b, c.fakeReadFrom)
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
		_, err = c.PacketConn.WriteTo(b2, addr)
	} else {
		_, err = c.Conn.Write(b2)
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
	net.PacketConn
	c        *Config
	sessions sync.Map
}

func NewMultiUDPConn(conn net.PacketConn, c *Config) *MultiUDPConn {
	return &MultiUDPConn{
		PacketConn: conn,
		c:          c,
	}
}

func (c *MultiUDPConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	b2 := bufPool.Get().([]byte)
	defer bufPool.Put(b2)
	for {
		n, addr, err = c.PacketConn.ReadFrom(b2)
		if err != nil {
			return
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
	_, err = c.PacketConn.WriteTo(b2, addr)
	return
}

func (c *MultiUDPConn) RemoveAddr(addr net.Addr) {
	c.sessions.Delete(addr.String())
}

type UDPTProxyConn struct {
	*net.UDPConn
}

func NewUDPTProxyConn(conn *net.UDPConn) (*UDPTProxyConn, error) {
	c := &UDPTProxyConn{UDPConn: conn}
	if err := redir.EnableUDPTProxy(conn); err != nil {
		return nil, err
	}
	return c, nil
}

func (conn *UDPTProxyConn) ReadFrom(b []byte) (n int, addr net.Addr, err error) {
	if len(b) < 6 {
		err = fmt.Errorf("the buffer length should be greater than 6")
		return
	}

	header := b[:6]
	b = b[6:]
	oob := make([]byte, 512)

	n, oobn, _, addr, err := conn.UDPConn.ReadMsgUDP(b, oob)
	if err != nil {
		return
	}
	orig, err := redir.GetOrigDstFromOob(oob[:oobn])
	if err != nil {
		return
	}
	copy(header, []byte(orig.IP.To4()))
	binary.BigEndian.PutUint16(header[4:6], uint16(orig.Port))
	n += 6
	return
}

func (conn *UDPTProxyConn) Read(b []byte) (n int, err error) {
	n, _, err = conn.ReadFrom(b)
	return
}
