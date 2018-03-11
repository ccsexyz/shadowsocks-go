package ss

import (
	"bytes"

	"github.com/ccsexyz/utils"
)

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

// Socks5Dialer implements Dialer interface
// and connect to the given address with socks5 protocol
type Socks5Dialer struct {
	Dialer
	raddr string
}

// NewSocks5Dialer get dialer with socks5 protocol
func NewSocks5Dialer(d Dialer, raddr string) Dialer {
	if d == nil {
		d = NewNetDialer()
	}
	return &Socks5Dialer{
		Dialer: d,
		raddr:  raddr,
	}
}

func (s *Socks5Dialer) Dial(network, target string) (Conn, error) {
	conn, err := s.Dialer.Dial(network, s.raddr)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()
	err = WriteBuffer(conn, []byte{0x5, 0x1, 0x0})
	if err != nil {
		return nil, err
	}
	buf := utils.GetBuf(bufferSize)
	defer utils.PutBuf(buf)
	b, err := conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(b, []byte{0x5, 0x0}) {
		err = errNotSocks5
		return nil, err
	}
	buf[0] = verSocks5
	buf[1] = cmdConnect
	buf[2] = 0x0
	addr := DstAddr{hostport: target}
	n := copy(buf[3:], addr.Header())
	err = WriteBuffer(conn, buf[:3+n])
	if err != nil {
		return nil, err
	}
	b, err = conn.ReadBuffer(buf)
	if err != nil {
		return nil, err
	}
	if len(b) < 3+minHeaderSize || b[0] != 0x05 {
		err = errNotSocks5
		return nil, err
	}
	b = b[3:]
	addr, n, err = ParseAddr(b)
	if err != nil {
		return nil, err
	}
	if n < len(b) {
		data := b[n:]
		conn = NewRemainConn(conn, data, nil)
	}
	return conn, err
}
