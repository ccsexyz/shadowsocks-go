package ss

import (
	"net"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

type Conn interface {
	utils.Conn
	GetCfg() *Config
	SetDst(Addr)
	GetDst() Addr
	GetHost() string
}

// AcceptedConn is the contract between the accept layer and the connection handler.
// It embeds Conn to satisfy net.Conn directly.
type AcceptedConn struct {
	Conn
	Target Addr
	Config *Config
}

// TargetStr returns the target address as a string.
func (ac *AcceptedConn) TargetStr() string {
	if ac.Target == nil {
		return ""
	}
	return ac.Target.String()
}

// Unwrapper provides access to the inner net.Conn for connection wrappers.
type Unwrapper interface {
	Unwrap() net.Conn
}

type cfg = Config

// BaseConn wraps a raw net.Conn with WriteBuffers support and connection metadata.
type BaseConn struct {
	net.Conn
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

func (c *BaseConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	buffers := net.Buffers(bufs)
	n64, err := buffers.WriteTo(c.Conn)
	return int(n64), err
}

func newBaseConn(conn net.Conn, cfg *cfg) *BaseConn {
	return &BaseConn{Conn: conn, cfg: cfg}
}

type LimitConn struct {
	Conn
	Rlimiters []*Limiter
	Wlimiters []*Limiter
}

func (c *LimitConn) Unwrap() net.Conn { return c.Conn }

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

func buildLimiters(c *Config) []*Limiter {
	limiters := make([]*Limiter, len(c.getLimiters()))
	copy(limiters, c.getLimiters())
	if c.LimitPerConn != 0 {
		limiters = append(limiters, NewLimiter(c.LimitPerConn))
	}
	return limiters
}

func limitAcceptHandler(conn Conn, lis *listener) AcceptResult {
	return AcceptResult{AcceptContinue, &LimitConn{
		Conn:      GetConn(conn),
		Rlimiters: buildLimiters(lis.c),
	}}
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
