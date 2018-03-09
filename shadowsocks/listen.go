package ss

import (
	"bytes"
	"errors"
	"log"
	"net"
	"strings"

	"github.com/ccsexyz/utils"
)

const (
	verSocks5   = 0x5
	verSocks6   = 0x6
	verSocks4   = 0x4
	cmdConnect  = 0x1
	cmdUDP      = 0x3
	cmdSocks4OK = 0x5A
	CtxTarget   = "target"
)

var (
	errNotSocks5      = errors.New("not socks5 protocol")
	errNotShadowsocks = errors.New("not shadowsocks protocol")
	errNotHTTPPorxy   = errors.New("not http proxy protocol")
	errUnExpected     = errors.New("unexpected error")
	errDuplicateIV    = errors.New("duplicated IV")
)

type ConnCtx struct {
	m map[string]interface{}
}

func NewConnCtx() *ConnCtx {
	return &ConnCtx{
		m: make(map[string]interface{}),
	}
}

func (ctx *ConnCtx) Store(key string, value interface{}) interface{} {
	v, _ := ctx.m[key]
	ctx.m[key] = value
	return v
}

func (ctx *ConnCtx) Get(key string) (interface{}, bool) {
	v, ok := ctx.m[key]
	return v, ok
}

type Acceptor interface {
	Accept(Conn, *ConnCtx) (Conn, error)
}

type Acceptors []Acceptor

func (accs *Acceptors) Accept(c net.Conn) {
	conn := NewConnFromNetConn(c)
	ctx := NewConnCtx()
	defer conn.Close()
	for _, acc := range *accs {
		newConn, err := acc.Accept(conn, ctx)
		if newConn != nil {
			conn = newConn
		}
		if err != nil {
			log.Println(err)
			break
		}
		if newConn == nil {
			break
		}
	}
}

type PickOneAcceptor []Acceptor

func NewPickOneAcceptor(acceptors ...Acceptor) Acceptor {
	var p PickOneAcceptor
	p = append(p, acceptors...)
	return &p
}

func (p *PickOneAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	for _, acc := range *p {
		newConn, err := acc.Accept(conn, ctx)
		if newConn != nil && err == nil {
			return newConn, nil
		}
		if newConn != nil && err != nil {
			conn = newConn
			continue
		}
		if newConn == nil && err == nil {
			conn.Close()
			return nil, errUnExpected
		}
		if newConn == nil && err != nil {
			conn.Close()
			return nil, err
		}
	}
	return nil, nil
}

type Socks5Acceptor struct{}

func NewSocks5Acceptor() Acceptor {
	return &Socks5Acceptor{}
}

func (s *Socks5Acceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	buf := utils.GetBuf(bufferSize)
	defer utils.PutBuf(buf)
	b, err := conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	errf := func() (Conn, error) {
		return NewRemainConn(conn, b, nil), errNotSocks5
	}
	if len(b) < 2 {
		return errf()
	}
	ver := b[0]
	nmethods := b[1]
	if ver != verSocks5 || len(b) != int(nmethods)+2 {
		return errf()
	}
	err = WriteBuffer(conn, []byte{5, 0})
	if err != nil {
		return nil, err
	}
	b, err = conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	ver = b[0]
	cmd := b[1]
	if ver != verSocks5 || (cmd != cmdConnect && cmd != cmdUDP) {
		return nil, errNotSocks5
	}
	addr, n, err := ParseAddr(b[3:])
	if err != nil {
		return nil, err
	}
	if n != len(b[3:]) {
		return nil, errNotSocks5
	}
	err = WriteBuffer(conn, []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return nil, err
	}
	ctx.Store(CtxTarget, addr)
	return conn, nil
}

type Socks4Acceptor struct{}

type ShadowSocksAcceptor struct {
	encMaker EncrypterMaker
	decMaker DecrypterMaker
	filter   bytesFilter
}

func NewShadowSocksAcceptor(method, password string) Acceptor {
	return &ShadowSocksAcceptor{
		encMaker: NewUtilsEncrypterMaker(method, password),
		decMaker: NewUtilsDecrypterMaker(method, password),
		filter:   newBloomFilter(),
	}
}

func (s *ShadowSocksAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	buf := utils.GetBuf(bufferSize)
	defer utils.PutBuf(buf)
	header := buf[bufferSize/2:]
	buf = buf[:bufferSize/2]
	b, err := conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	errf := func() (Conn, error) {
		return NewRemainConn(conn, b, nil), errNotShadowsocks
	}
	ivlen := s.decMaker.Ivlen()
	if len(b) < ivlen+minHeaderSize {
		return errf()
	}
	dec, err := s.decMaker.Make(b[:ivlen])
	if err != nil {
		return NewRemainConn(conn, b, nil), err
	}
	dec.Decrypt(header, b[ivlen:])
	header = header[:len(b[ivlen:])]
	addr, n, err := ParseAddr(header)
	if err != nil {
		return NewRemainConn(conn, b, nil), err
	}
	if s.filter.TestAndAdd(b[:ivlen]) {
		log.Println("recv duplicated iv from", conn.RemoteAddr(), b[:ivlen])
		return nil, errDuplicateIV
	}
	ctx.Store(CtxTarget, addr)
	data := b[ivlen+n:]
	if len(data) > 0 {
		conn = NewRemainConn(conn, data, nil)
	}
	conn = NewShadowSocksConn(conn, s.encMaker, s.decMaker)
	ssConn := conn.(*ShadowSocksConn)
	dec, err = s.decMaker.Make(b[:ivlen])
	if err != nil {
		return NewRemainConn(conn, b, nil), err
	}
	dec.Decrypt(b[ivlen:n+ivlen], b[ivlen:n+ivlen])
	ssConn.dec = dec
	return conn, nil
}

type HTTPProxyAcceptor struct{}

func NewHTTPProxyAcceptor() Acceptor {
	return &HTTPProxyAcceptor{}
}

func (h *HTTPProxyAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	parser := utils.NewHTTPHeaderParser(utils.GetBuf(bufferSize))
	defer utils.PutBuf(parser.GetBuf())
	buf := utils.GetBuf(bufferSize)
	defer utils.PutBuf(buf)
	b, err := conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	ok, err := parser.Read(b)
	if err != nil {
		return NewRemainConn(conn, b, nil), err
	}
	var requestMethod, requestURI []byte
	if ok {
		requestMethod, err = parser.GetFirstLine1()
		if err == nil {
			requestURI, err = parser.GetFirstLine2()
		}
	}
	if !ok || err != nil {
		return NewRemainConn(conn, b, nil), errNotHTTPPorxy
	}
	uri := utils.SliceToString(requestURI)
	var host, port string
	if bytes.Equal(requestMethod, []byte("CONNECT")) {
		host, port, err = net.SplitHostPort(uri)
		if err != nil {
			return nil, err
		}
		err = WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		if err != nil {
			return nil, err
		}
		ctx.Store(CtxTarget, DstAddr{host: host, port: port})
		return conn, nil
	}
	if bytes.HasPrefix(requestURI, []byte("http://")) {
		requestURI = requestURI[7:]
	}
	it := bytes.IndexByte(requestURI, '/')
	if it < 0 {
		return nil, errNotHTTPPorxy
	}
	ok = parser.StoreFirstline2(requestURI[it:])
	if !ok {
		return nil, errNotHTTPPorxy
	}
	hosts, ok := parser.Load([]byte("Host"))
	if !ok || len(hosts) == 0 || len(hosts[0]) == 0 {
		return nil, errNotHTTPPorxy
	}
	dst := string(hosts[0])
	it = strings.Index(dst, ":")
	if it < 0 {
		dst = dst + ":80"
	}
	host, port, err = net.SplitHostPort(dst)
	if err != nil {
		return nil, err
	}
	proxys, ok := parser.Load([]byte("Proxy-Connection"))
	if ok && len(proxys) > 0 && len(proxys[0]) > 0 {
		parser.Store([]byte("Connection"), proxys[0])
		parser.Delete([]byte("Proxy-Connection"))
	}
	n, err := parser.Encode(buf)
	if err != nil {
		return nil, err
	}
	conn = NewRemainConn(conn, buf[:n], nil)
	ctx.Store(CtxTarget, DstAddr{host: host, port: port})
	return conn, nil
}
