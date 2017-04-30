package shadowsocks

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/ccsexyz/utils"
)

type Conn utils.Conn

type conn struct {
	net.Conn
}

func Newconn(c net.Conn) *conn {
	return &conn{Conn: c}
}

func (c *conn) WriteBuffers(b [][]byte) (n int, err error) {
	buffers := net.Buffers(b)
	var n2 int64
	n2, err = buffers.WriteTo(c)
	n = int(n2)
	return
}

var (
	xuch  chan net.Conn
	xudie chan bool
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

type SsConn struct {
	Conn
	enc  Encrypter
	dec  Decrypter
	rbuf []byte
	wbuf []byte
	c    *Config
	xu1s bool
}

func (c *SsConn) GetConfig() *Config {
	return c.c
}

func (c *SsConn) Close() error {
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

func NewSsConn(conn Conn, c *Config) *SsConn {
	return &SsConn{
		Conn: conn,
		c:    c,
		rbuf: make([]byte, buffersize),
		wbuf: make([]byte, buffersize),
	}
}

func (c *SsConn) Xu1s() {
	c.xu1s = true
}

func (c *SsConn) Xu0s() {
	c.xu1s = false
}

func (c *SsConn) Read(b []byte) (n int, err error) {
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

func (c *SsConn) initEncrypter() (err error) {
	if c.enc == nil {
		c.enc, err = NewEncrypter(c.c.Method, c.c.Password)
	}
	return
}

func (c *SsConn) Write(b []byte) (n int, err error) {
	bufs := make([][]byte, 0, 2)
	if c.enc == nil {
		c.enc, err = NewEncrypter(c.c.Method, c.c.Password)
		if err != nil {
			return
		}
		bufs = append(bufs, c.enc.GetIV())
	}
	buf := make([]byte, len(b))
	c.enc.Encrypt(buf, b)
	bufs = append(bufs, buf)
	_, err = c.Conn.WriteBuffers(bufs)
	if err == nil {
		n = len(b)
	}
	return
}

func (c *SsConn) WriteBuffers(b [][]byte) (n int, err error) {
	bufs := make([][]byte, 0, len(b)+1)
	if c.enc == nil {
		c.enc, err = NewEncrypter(c.c.Method, c.c.Password)
		if err != nil {
			return
		}
		bufs = append(bufs, c.enc.GetIV())
	}
	for it := 0; it < len(b); it++ {
		buf := make([]byte, len(b[it]))
		c.enc.Encrypt(buf, b[it])
		bufs = append(bufs, buf)
		n += len(b[it])
	}
	_, err = c.Conn.WriteBuffers(bufs)
	if err != nil {
		n = 0
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
				b = rand.Intn(16) + 1
				a += b
			}
			if _, ok := c.(*SsConn); ok {
				c.(*SsConn).c.Log("xu ", a, "seconds")
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
						if _, ok := c.(*SsConn); ok {
							c.(*SsConn).xu1s = false
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
	Conn
}

// FIXME
func NewConn2(conn Conn) Conn {
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
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf[:], uint16(n))
	_, err = c.Conn.WriteBuffers([][]byte{buf, b})
	if err != nil {
		n = 0
	}
	return
}

func (c *Conn2) WriteBuffers(b [][]byte) (n int, err error) {
	for _, v := range b {
		var nbytes int
		nbytes, err = c.Write(v)
		if err != nil {
			return
		}
		n += nbytes
	}
	return
}

type DstConn struct {
	Conn
	dst Addr
}

func NewDstConn(conn net.Conn, dst Addr) *DstConn {
	return &DstConn{Conn: GetConn(conn), dst: dst}
}

func (c *DstConn) GetDst() string {
	return net.JoinHostPort(c.dst.Host(), c.dst.Port())
}

type LimitConn struct {
	Conn
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

func (c *LimitConn) WriteBuffers(b [][]byte) (n int, err error) {
	n, err = c.Conn.WriteBuffers(b)
	if err == nil {
		for _, v := range c.Wlimiters {
			v.Update(n)
		}
	}
	return
}

func limitAcceptHandler(conn Conn, lis *listener) (c Conn) {
	limiters := make([]*Limiter, len(lis.c.limiters))
	copy(limiters, lis.c.limiters)
	if lis.c.LimitPerConn != 0 {
		limiters = append(limiters, NewLimiter(lis.c.LimitPerConn))
	}
	c = &LimitConn{
		Conn:      GetConn(conn),
		Rlimiters: limiters,
	}
	return
}

type MuxConn struct {
	conn Conn
	Conn
}
