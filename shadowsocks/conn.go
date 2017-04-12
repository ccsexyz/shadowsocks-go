package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"
)

var (
	xuch  chan net.Conn
	xudie chan bool
	src   = rand.NewSource(time.Now().UnixNano())
)

func init() {
	xuch = make(chan net.Conn, 32)
	xudie = make(chan bool)
	go xuroutine()
}

type DebugConn struct {
	net.Conn
	c *Config
}

func NewDebugConn(conn net.Conn, c *Config) *DebugConn {
	return &DebugConn{Conn: conn, c: c}
}

func (c *DebugConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err == nil && n > 0 {
		c.c.LogD("read", n, "bytes from", c.RemoteAddr(), b[:n])
	}
	return
}

func (c *DebugConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if err == nil && n > 0 {
		c.c.LogD("write", n, "bytes to", c.RemoteAddr(), "from", c.LocalAddr(), b[:n])
	}
	return
}

func debugAcceptHandler(conn net.Conn, lis *listener) (c net.Conn) {
	if lis.c.Debug {
		c = &DebugConn{
			Conn: conn,
			c:    lis.c,
		}
	} else {
		c = conn
	}
	return
}

type Conn struct {
	net.Conn
	enc  Encrypter
	dec  Decrypter
	rbuf []byte
	wbuf []byte
	c    *Config
	xu1s bool
}

func (c *Conn) GetConfig() *Config {
	return c.c
}

func (c *Conn) Close() error {
	if c.xu1s {
		c.xu1s = false
		select {
		case <-xudie:
		case xuch <- c:
			return nil
		}
	}
	return c.Conn.Close()
}

func NewConn(conn net.Conn, c *Config) *Conn {
	return &Conn{
		Conn: conn,
		c:    c,
		rbuf: make([]byte, buffersize),
		wbuf: make([]byte, buffersize),
	}
}

func (c *Conn) Xu1s() {
	c.xu1s = true
}

func (c *Conn) Xu0s() {
	c.xu1s = false
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		_, err = io.ReadFull(c.Conn, c.rbuf[:c.c.Ivlen])
		if err != nil {
			return
		}
		c.dec, err = NewDecrypter(c.c.Method, c.c.Password, c.rbuf[:c.c.Ivlen])
		if err != nil {
			return
		}
	}
	rbuf := c.rbuf
	if len(c.rbuf) > len(b) {
		rbuf = rbuf[:len(b)]
	}
	n, err = c.Conn.Read(rbuf)
	if n > 0 {
		c.dec.Decrypt(b[:n], rbuf[:n])
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.enc == nil {
		c.enc, err = NewEncrypter(c.c.Method, c.c.Password)
		if err != nil {
			return
		}
		iv := c.enc.GetIV()
		copy(c.wbuf, iv)
		n += len(iv)
	}
	var r []byte
	if len(b) > len(c.wbuf[n:]) {
		r = b[len(c.wbuf[n:]):]
		b = b[:len(c.wbuf[n:])]
	}
	c.enc.Encrypt(c.wbuf[n:], b)
	n, err = c.Conn.Write(c.wbuf[:n+len(b)])
	if err == nil && r != nil {
		var nbytes int
		nbytes, err = c.Write(r)
		n += nbytes
	}
	return
}

func xuroutine() {
	ticker := time.NewTicker(time.Second)
	mn := make(map[string]int)
	mc := make(map[string]net.Conn)
	defer func() {
		for _, v := range mc {
			v.Close()
		}
	}()
	for {
		select {
		case <-xudie:
			return
		case c := <-xuch:
			s := c.RemoteAddr().String()
			a := 0
			b := 0
			for b < 3 || b > 14 {
				b = int(src.Int63()%16 + 1)
				a += b
			}
			if _, ok := c.(*Conn); ok {
				c.(*Conn).c.Log("you have xu ", a, "seconds")
			}
			mn[s] = a
			mc[s] = c
		case <-ticker.C:
			for k, v := range mn {
				v--
				if v <= 0 {
					delete(mn, k)
					c, ok := mc[k]
					if ok {
						delete(mc, k)
						if _, ok := c.(*Conn); ok {
							c.(*Conn).xu1s = false
						}
						c.Close()
					}
				} else {
					mn[k] = v
				}
			}
		}
	}
}

// FIXME
type Conn2 struct {
	net.Conn
}

// FIXME
func NewConn2(conn net.Conn) net.Conn {
	return &Conn2{
		Conn: conn,
	}
}

func (c *Conn2) Read(b []byte) (n int, err error) {
	_, err = io.ReadFull(c.Conn, b[:2])
	if err != nil {
		return
	}
	nbytes := binary.BigEndian.Uint16(b[:2])
	if nbytes > 1500 {
		err = fmt.Errorf("wrong nbytes %d", nbytes)
		return
	}
	_, err = io.ReadFull(c.Conn, b[:int(nbytes)])
	if err != nil {
		return
	}
	n = int(nbytes)
	return
}

func (c *Conn2) Write(b []byte) (n int, err error) {
	n = len(b)
	if n > 1500 {
		err = fmt.Errorf("cannot write %d bytes", n)
		return
	}
	var buf [2048]byte
	binary.BigEndian.PutUint16(buf[:], uint16(n))
	copy(buf[2:], b)
	_, err = c.Conn.Write(buf[:n+2])
	return
}

type DstConn struct {
	net.Conn
	dst Addr
}

func NewDstConn(conn net.Conn, dst Addr) *DstConn {
	return &DstConn{Conn: conn, dst: dst}
}

func (c *DstConn) GetDst() string {
	return net.JoinHostPort(c.dst.Host(), c.dst.Port())
}

type LimitConn struct {
	net.Conn
	Rlimiters []*Limiter
	Wlimiters []*Limiter
}

func (c *LimitConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if err == nil {
		for _, v := range c.Rlimiters {
			v.Update(n)
		}
	}
	return
}

func (c *LimitConn) Write(b []byte) (n int, err error) {
	n, err = c.Conn.Write(b)
	if err == nil {
		for _, v := range c.Wlimiters {
			v.Update(n)
		}
	}
	return
}

func limitAcceptHandler(conn net.Conn, lis *listener) (c net.Conn) {
	limiters := make([]*Limiter, len(lis.c.limiters))
	copy(limiters, lis.c.limiters)
	if lis.c.LimitPerConn != 0 {
		limiters = append(limiters, NewLimiter(lis.c.LimitPerConn))
	}
	c = &LimitConn{
		Conn:      conn,
		Rlimiters: limiters,
	}
	return
}

type MuxConn struct {
	conn net.Conn
	net.Conn
}
