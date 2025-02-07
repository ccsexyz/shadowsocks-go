package ss

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	"github.com/ccsexyz/shadowsocks-go/redir"
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
	cb, err := utils.NewCipherBlock(c.c.Method, c.c.Password)
	if err != nil {
		return 0, nil, err
	}

	b2 := make([]byte, len(b))
	for {
		n, addr, err := readfrom(b)
		if err != nil {
			return 0, addr, err
		}

		p, iv, err := cb.Decrypt(b2, b[:n])
		if err != nil {
			if err == io.ErrShortBuffer {
				continue
			}

			return 0, addr, err
		}

		if len(iv) > 0 {
			exists := c.c.udpFilterTestAndAdd(iv)
			if exists {
				continue
			}
		}

		n = copy(b, p)
		return n, addr, err
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
	cb, err := utils.NewCipherBlock(c.c.Method, c.c.Password)
	if err != nil {
		return
	}
	b2, _, err := cb.Encrypt(nil, b)
	if err != nil {
		return
	}
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
	b2 := utils.GetBuf(buffersize)
	defer utils.PutBuf(b2)
	for {
		n, addr, err = c.PacketConn.ReadFrom(b2)
		if err != nil {
			return
		}
		v, ok := c.sessions.Load(addr.String())
		if !ok {
			ctx, err := ParseAddrWithMultipleBackendsForUDP(b2[:n], c.c.Backends)
			if err != nil {
				continue
			}
			exists := ctx.chs.udpFilterTestAndAdd(ctx.iv)
			if exists {
				continue
			}
			c.sessions.Store(addr.String(), ctx.chs)
			// *(chs.Any.(*int))++
			ctx.chs.LogD("udp mode choose", ctx.chs.Method, ctx.chs.Password)
			n = copy(b, ctx.addr.header)
			n += copy(b[n:], ctx.data)
		} else {
			cfg := v.(*Config)
			var cb utils.CipherBlock
			cb, err = utils.NewCipherBlock(cfg.Method, cfg.Password)
			if err != nil {
				return
			}
			var p []byte
			var iv []byte
			p, iv, err = cb.Decrypt(b, b2[:n])
			if err != nil {
				return
			}
			if len(iv) > 0 {
				exists := cfg.udpFilterTestAndAdd(iv)
				if exists {
					continue
				}
			}
			n = copy(b, p)
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
	cb, err := utils.NewCipherBlock(cfg.Method, cfg.Password)
	if err != nil {
		return
	}
	b2, _, err := cb.Encrypt(nil, b)
	if err != nil {
		return
	}
	return c.PacketConn.WriteTo(b2, addr)
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
