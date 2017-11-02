package ss

import (
	"io"
	"math/rand"
	"net"
	"time"

	"github.com/ccsexyz/utils"
)

type Conn interface {
	utils.Conn
	GetCfg() *Config
	SetDst(Addr)
	GetDst() Addr
}

type cfg = Config

type cfgCtx struct {
	c *Config
}

func (ctx *cfgCtx) GetCfg() *Config {
	return ctx.c
}

type dstCtx struct {
	dst Addr
}

func (ctx *dstCtx) SetDst(dst Addr) {
	ctx.dst = dst
}

func (ctx *dstCtx) GetDst() Addr {
	return ctx.dst
}

type TCPConn struct {
	utils.Conn
	cfgCtx
	dstCtx
}

func newTCPConn(conn utils.Conn, cfg *cfg) *TCPConn {
	return &TCPConn{
		Conn: conn,
		cfgCtx: cfgCtx{
			c: cfg,
		},
	}
}

func newTCPConn2(conn net.Conn, cfg *cfg) *TCPConn {
	return newTCPConn(utils.NewConn(conn), cfg)
}

type DebugConn struct {
	Conn
	c *Config
}

func NewDebugConn(conn Conn, c *Config) *DebugConn {
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

func debugAcceptHandler(conn Conn, lis *listener) (c Conn) {
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
	enc        utils.Encrypter
	dec        utils.Decrypter
	c          *Config
	xu1s       bool
	reqenc     bool
	encnum     int
	reqdec     bool
	decnum     int
	partenc    bool
	partencnum int
}

func (c *SsConn) GetConfig() *Config {
	return c.c
}

func (c *SsConn) Close() error {
	if c.xu1s {
		go func() {
			time.Sleep(time.Duration(rand.Int()%64+8) * time.Second)
			c.Conn.Close()
		}()
		return nil
	}
	return c.Conn.Close()
}

func NewSsConn(conn Conn, c *Config) *SsConn {
	return &SsConn{
		Conn:   conn,
		c:      c,
		reqdec: true,
		reqenc: true,
	}
}

func (c *SsConn) Xu1s() {
	c.xu1s = true
}

func (c *SsConn) Xu0s() {
	c.xu1s = false
}

func (c *SsConn) Read(b []byte) (n int, err error) {
	if c.partenc && !c.reqdec {
		c.dec = nil
		return c.Conn.Read(b)
	}
	if len(b) < c.c.Ivlen {
		err = io.ErrShortBuffer
		return
	}
	off := 0
	if c.dec == nil {
		n, err = io.ReadAtLeast(c.Conn, b, c.c.Ivlen)
		if err == nil {
			c.dec, err = utils.NewDecrypter(c.c.Method, c.c.Password, b[:c.c.Ivlen])
			if err == nil {
				off = c.c.Ivlen
				n -= off
			}
		}
	} else {
		n, err = c.Conn.Read(b)
	}
	if err != nil {
		return
	}
	if !c.partenc {
		if n == 0 {
			return c.Read(b)
		}
		c.dec.Decrypt(b[:n], b[off:n+off])
		return
	}
	if c.decnum+n >= c.partencnum {
		m := c.partencnum - c.decnum
		if off == 0 {
			c.dec.Decrypt(b[:m], b[:m])
		} else {
			c.dec.Decrypt(b[:m], b[off:off+m])
			copy(b[m:], b[off+m:off+n])
		}
		c.reqdec = false
	} else {
		c.decnum += n
		c.dec.Decrypt(b[:n], b[off:n+off])
	}
	return
}

func (c *SsConn) initEncrypter() (err error) {
	if c.enc == nil {
		c.enc, err = utils.NewEncrypter(c.c.Method, c.c.Password)
	}
	return
}

func (c *SsConn) Write(b []byte) (n int, err error) {
	if c.partenc && !c.reqenc {
		c.enc = nil
		return c.Conn.Write(b)
	}
	bufs := make([][]byte, 0, 2)
	if c.enc == nil {
		c.enc, err = utils.NewEncrypter(c.c.Method, c.c.Password)
		if err != nil {
			return
		}
		bufs = append(bufs, c.enc.GetIV())
	}
	if !c.partenc {
		c.enc.Encrypt(b, b)
	} else {
		if c.reqenc {
			if c.encnum+len(b) >= c.partencnum {
				m := c.partencnum - c.encnum
				c.enc.Encrypt(b[:m], b[:m])
				c.reqenc = false
			} else {
				c.encnum += len(b)
				c.enc.Encrypt(b, b)
			}
		}
	}
	bufs = append(bufs, b)
	_, err = c.Conn.WriteBuffers(bufs)
	if err == nil {
		n = len(b)
	}
	return
}

func (c *SsConn) WriteBuffers(b [][]byte) (n int, err error) {
	if c.partenc && !c.reqenc {
		c.enc = nil
		return c.Conn.WriteBuffers(b)
	}
	bufs := make([][]byte, 0, len(b)+1)
	if c.enc == nil {
		c.enc, err = utils.NewEncrypter(c.c.Method, c.c.Password)
		if err != nil {
			return
		}
		bufs = append(bufs, c.enc.GetIV())
	}
	for it := 0; it < len(b); it++ {
		buf := b[it]
		if !c.partenc {
			c.enc.Encrypt(buf, buf)
		} else {
			if c.reqenc {
				if c.encnum+len(buf) >= c.partencnum {
					m := c.partencnum - c.encnum
					c.enc.Encrypt(buf[:m], buf[:m])
					c.reqenc = false
				} else {
					c.encnum += len(buf)
					c.enc.Encrypt(buf, buf)
				}
			}
		}
		bufs = append(bufs, buf)
		n += len(b[it])
	}
	_, err = c.Conn.WriteBuffers(bufs)
	if err != nil {
		n = 0
	}
	return
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

type HttpLogConn struct {
	Conn
	pr *utils.HTTPHeaderParser
	pw *utils.HTTPHeaderParser
	c  *Config
}

func NewHttpLogConn(conn Conn, c *Config) *HttpLogConn {
	return &HttpLogConn{
		Conn: conn,
		pr:   utils.NewHTTPHeaderParser(utils.GetBuf(httpbuffersize)),
		pw:   utils.NewHTTPHeaderParser(utils.GetBuf(httpbuffersize)),
		c:    c,
	}
}

func cleanHTTPParser(p *utils.HTTPHeaderParser) {
	if p != nil {
		utils.PutBuf(p.GetBuf())
	}
}

func (conn *HttpLogConn) Close() error {
	if conn.pr != nil {
		cleanHTTPParser(conn.pr)
		conn.pr = nil
	}
	if conn.pw != nil {
		cleanHTTPParser(conn.pw)
		conn.pw = nil
	}
	return conn.Conn.Close()
}

func (conn *HttpLogConn) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	if conn.pr != nil {
		ok, e := conn.pr.Read(b[:n])
		if ok {
			var n2 int
			buf := utils.GetBuf(httpbuffersize)
			defer utils.PutBuf(buf)
			n2, e = conn.pr.Encode(buf)
			if err == nil {
				conn.c.Log(conn.LocalAddr(), "->", conn.RemoteAddr(), utils.SliceToString(buf[:n2]))
			}
		}
		if e != nil || ok {
			cleanHTTPParser(conn.pr)
			conn.pr = nil
		}

	}
	return
}

func (conn *HttpLogConn) Write(b []byte) (n int, err error) {
	if conn.pw != nil {
		ok, e := conn.pw.Read(b)
		if ok {
			var n2 int
			buf := utils.GetBuf(httpbuffersize)
			defer utils.PutBuf(buf)
			n2, e = conn.pw.Encode(buf)
			if err == nil {
				conn.c.Log(conn.LocalAddr(), "->", conn.RemoteAddr(), utils.SliceToString(buf[:n2]))
			}
		}
		if e != nil || ok {
			cleanHTTPParser(conn.pw)
			conn.pw = nil
		}

	}
	return conn.Conn.Write(b)
}
