package ss

import (
	"io"
	"net"
	"time"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

// Conn is a byte-stream connection with zero-copy read and scatter-gather write.
type Conn interface {
	Read(buf []byte, pool *utils.BufPool) (segs [][]byte, err error)
	Write(bufs ...[]byte) (n int, err error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// ConnMeta provides shadowsocks-specific metadata access.
type ConnMeta interface {
	GetCfg() *Config
	SetDst(Addr)
	GetDst() Addr
	GetHost() string
}

// AcceptedConn is the contract between the accept layer and the connection handler.
type AcceptedConn struct {
	Conn
	Target Addr
	Config *Config
}

func (ac *AcceptedConn) TargetStr() string {
	if ac.Target == nil {
		return ""
	}
	return ac.Target.String()
}

// Unwrapper provides access to the inner Conn.
type Unwrapper interface {
	Unwrap() Conn
}

// getConnMeta unwraps conn to find the first type that implements ConnMeta.
func getConnMeta(conn Conn) ConnMeta {
	for {
		if cm, ok := conn.(ConnMeta); ok {
			return cm
		}
		if u, ok := conn.(Unwrapper); ok {
			conn = u.Unwrap()
		} else {
			return nil
		}
	}
}

// AsReader wraps a Conn as an io.Reader using the given pool for buffers.
func AsReader(c Conn, pool *utils.BufPool) io.Reader {
	return &connReader{Conn: c, pool: pool}
}

type connReader struct {
	Conn
	pool *utils.BufPool
	buf  []byte // buffered excess from previous Read
}

func (r *connReader) Read(p []byte) (int, error) {
	// Serve buffered data first.
	if len(r.buf) > 0 {
		n := copy(p, r.buf)
		r.buf = r.buf[n:]
		return n, nil
	}
	segs, err := r.Conn.Read(p, r.pool)
	if err != nil {
		return 0, err
	}
	if len(segs) == 1 && len(segs[0]) <= len(p) {
		return copy(p, segs[0]), nil
	}
	// Multi-segment or oversized: flatten into pool or heap, buffer excess.
	total := 0
	for _, s := range segs {
		total += len(s)
	}
	var flat []byte
	if r.pool != nil {
		flat = r.pool.Get(total)
	} else {
		flat = make([]byte, total)
	}
	off := 0
	for _, s := range segs {
		off += copy(flat[off:], s)
	}
	n := copy(p, flat)
	if n < total {
		r.buf = flat[n:]
	}
	return n, nil
}

func (r *connReader) WriteTo(w io.Writer) (int64, error) { return 0, io.ErrUnexpectedEOF }

// AsReadWriteCloser wraps c as io.ReadWriteCloser for libraries like smux.
func AsReadWriteCloser(c Conn, pool *utils.BufPool) io.ReadWriteCloser {
	return &connRWCloser{connReader: connReader{Conn: c, pool: pool}}
}

type connRWCloser struct {
	connReader
}

func (r *connRWCloser) Write(p []byte) (int, error) {
	n, err := r.Conn.Write(p)
	return n, err
}

// AsNetConn wraps a net.Conn as a Conn.
func AsNetConn(c net.Conn) Conn { return &BaseConn{raw: c} }

type cfg = Config

// BaseConn adapts a raw net.Conn to Conn.
type BaseConn struct {
	raw  net.Conn
	cfg  *Config
	dst  Addr
	host string
}

func (c *BaseConn) GetCfg() *Config     { return c.cfg }
func (c *BaseConn) SetCfg(cfg *Config)  { c.cfg = cfg }
func (c *BaseConn) SetDst(dst Addr)     { c.dst = dst }
func (c *BaseConn) SetHost(host string) { c.host = host }
func (c *BaseConn) GetDst() Addr        { return c.dst }
func (c *BaseConn) GetHost() string     { return c.host }
func (c *BaseConn) Unwrap() Conn        { return nil }

func (c *BaseConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	var b []byte
	if buf != nil {
		b = buf
	} else if pool != nil {
		b = pool.Get(65536)
	} else {
		b = make([]byte, 65536)
	}
	n, err := c.raw.Read(b)
	if err != nil {
		return nil, err
	}
	return [][]byte{b[:n]}, nil
}

func (c *BaseConn) Write(bufs ...[]byte) (n int, err error) {
	nb := net.Buffers(bufs)
	n64, err := nb.WriteTo(c.raw)
	return int(n64), err
}

func (c *BaseConn) Close() error                       { return c.raw.Close() }
func (c *BaseConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *BaseConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *BaseConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *BaseConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *BaseConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }

func newBaseConn(conn net.Conn, cfg *cfg) *BaseConn {
	return &BaseConn{raw: conn, cfg: cfg}
}

// LimitConn wraps Conn with rate limiting.
type LimitConn struct {
	Conn
	Rlimiters []*Limiter
	Wlimiters []*Limiter
}

func (c *LimitConn) Unwrap() Conn { return c.Conn }

func (c *LimitConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	segs, err := c.Conn.Read(buf, pool)
	if err == nil {
		n := 0
		for _, s := range segs {
			n += len(s)
		}
		for _, v := range c.Rlimiters {
			v.Update(n)
		}
	}
	return segs, err
}

func (c *LimitConn) Write(bufs ...[]byte) (n int, err error) {
	n, err = c.Conn.Write(bufs...)
	if err == nil {
		for _, v := range c.Wlimiters {
			v.Update(n)
		}
	}
	return
}

func (c *LimitConn) GetCfg() *Config {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetCfg()
	}
	return nil
}
func (c *LimitConn) SetDst(dst Addr) {
	if cm := getConnMeta(c.Conn); cm != nil {
		cm.SetDst(dst)
	}
}
func (c *LimitConn) GetDst() Addr {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetDst()
	}
	return nil
}
func (c *LimitConn) GetHost() string {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetHost()
	}
	return ""
}

func buildLimiters(c *Config) []*Limiter {
	limiters := make([]*Limiter, len(c.getLimiters()))
	copy(limiters, c.getLimiters())
	if c.LimitPerConn != 0 {
		limiters = append(limiters, NewLimiter(c.LimitPerConn))
	}
	return limiters
}

// HttpLogConn logs HTTP traffic for debugging.
type HttpLogConn struct {
	Conn
	pr, pw *utils.HTTPHeaderParser
	c      *Config
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

func (conn *HttpLogConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	segs, err := conn.Conn.Read(buf, pool)
	if err == nil && conn.pr != nil && len(segs) > 0 {
		ok, e := conn.pr.Read(segs[0])
		if ok {
			buf := utils.GetBuf(httpbuffersize)
			defer utils.PutBuf(buf)
			n2, _ := conn.pr.Encode(buf)
			conn.c.Log(conn.LocalAddr(), "->", conn.RemoteAddr(), utils.SliceToString(buf[:n2]))
		}
		if e != nil || ok {
			cleanHTTPParser(conn.pr)
			conn.pr = nil
		}
	}
	return segs, err
}

func (conn *HttpLogConn) Write(bufs ...[]byte) (n int, err error) {
	if conn.pw != nil && len(bufs) > 0 {
		ok, _ := conn.pw.Read(bufs[0])
		if ok {
			buf := utils.GetBuf(httpbuffersize)
			defer utils.PutBuf(buf)
			n2, _ := conn.pw.Encode(buf)
			conn.c.Log(conn.LocalAddr(), "->", conn.RemoteAddr(), utils.SliceToString(buf[:n2]))
		}
		if ok {
			cleanHTTPParser(conn.pw)
			conn.pw = nil
		}
	}
	return conn.Conn.Write(bufs...)
}

// ReadN reads from c into buf, returning total byte count.
// Uses AsReader internally to support partial reads from frame-based conns.
func ReadN(c Conn, buf []byte, pool *utils.BufPool) (int, error) {
	return AsReader(c, pool).Read(buf)
}
