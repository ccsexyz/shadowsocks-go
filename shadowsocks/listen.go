package ss

import (
	"errors"
	"log"
	"net"

	"github.com/ccsexyz/utils"
	"github.com/ccsexyz/shadowsocks-go/redir"
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
	errNotSocks5          = errors.New("not socks5 protocol")
	errNotShadowsocks     = errors.New("not shadowsocks protocol")
	errNotAEADShadowsocks = errors.New("not aead shadowsocks protocol")
	errNotHTTPPorxy       = errors.New("not http proxy protocol")
	errUnExpected         = errors.New("unexpected error")
	errDuplicateIV        = errors.New("duplicated IV")
	errCantGetDst = errors.New("can't get original destination")
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
	log.Println(len(b), ivlen, n)
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

type AEADShadowSocksAcceptor struct {
	encMaker *SSAeadEncrypterMaker
	decMaker *SSAeadDecrypterMaker
	filter   bytesFilter
}

func NewAEADShadowSocksAcceptor(method, password string) Acceptor {
	return &AEADShadowSocksAcceptor{
		encMaker: NewSSAeadEncrypterMaker(method, password),
		decMaker: NewSSAeadDecrypterMaker(method, password),
		filter:   newBloomFilter(),
	}
}

func (a *AEADShadowSocksAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	buf := utils.GetBuf(bufferSize)
	defer utils.PutBuf(buf)
	b, err := conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	ivlen := a.decMaker.ivlen
	if len(b) < ivlen+minHeaderSize {
		return NewRemainConn(conn, b, nil), errNotAEADShadowsocks
	}
	iv := utils.CopyBuffer(b[:ivlen])
	defer utils.PutBuf(iv)
	dec, err := a.decMaker.Make(iv)
	if err != nil {
		return NewRemainConn(conn, b, nil), err
	}
	lbuf := utils.GetBuf(16)
	defer utils.PutBuf(lbuf)
	err = dec.Decrypt(lbuf, b[ivlen:ivlen+2+dec.Overhead()])
	if err != nil {
		return NewRemainConn(conn, b, nil), err
	}
	dec = nil
	conn = NewRemainConn(conn, b[ivlen:], nil)
	conn = NewAEADShadowSocksConn(conn, a.encMaker, nil)
	aeadSsConn := conn.(*AEADShadowSocksConn)
	aeadSsConn.dec, err = a.decMaker.Make(b[:ivlen])
	if err != nil {
		return nil, err
	}
	b, err = conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	addr, n, err := ParseAddr(b)
	if err != nil {
		return nil, err
	}
	if a.filter.TestAndAdd(iv) {
		log.Println("recv duplicated iv from", conn.RemoteAddr(), b[:ivlen])
		return nil, errDuplicateIV
	}
	ctx.Store(CtxTarget, addr)
	data := b[n:]
	if len(data) > 0 {
		conn = NewRemainConn(conn, data, nil)
	}
	return conn, nil
}

type RedirAcceptor struct {}

func NewRedirAcceptor() Acceptor {
	return &RedirAcceptor{}
}

func (r *RedirAcceptor) Accept(conn Conn, ctx *ConnCtx) (Conn, error) {
	tcpConn, err := GetNetTCPConn(conn)
	if err != nil {
		return conn, err
	}
	origDst, err := redir.GetOrigDst(tcpConn)
	if err != nil || len(origDst) == 0 {
		return conn, errCantGetDst
	}
	log.Println(origDst)
	ctx.Store(CtxTarget, origDst)
	return conn, nil
}
