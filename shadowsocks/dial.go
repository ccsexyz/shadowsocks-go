package ss

import (
	"crypto/tls"
	"net"
)

// Dialer a Dialer is a means to establish a connection
type Dialer interface {
	// Dial connects to the given address via the proxy
	Dial(network, addr string) (Conn, error)
}

// NetDialer wraps net.Dial
type NetDialer struct{}

// Dial directly calls net.Dial and convert net.Conn to Conn
func (nd *NetDialer) Dial(network, addr string) (Conn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return NewConnFromNetConn(conn), nil
}

// TLSDialer wraps tls.Dial
type TLSDialer struct{}

// Dial directly calls tls.Dial and convert tls.Conn to Conn
func (td *TLSDialer) Dial(network, addr string) (Conn, error) {
	conn, err := tls.Dial(network, addr, nil)
	if err != nil {
		return nil, err
	}
	return NewConnFromNetConn(conn), nil
}

// NewNetDialer initicate a default Dialer that calls net.Dial
func NewNetDialer() Dialer {
	return &NetDialer{}
}

// ShadowSocksDialer implements proxy.Dialer interface
// and connect to the given address with ss protocol
type ShadowSocksDialer struct {
	Dialer
	raddr    string
	encMaker EncrypterMaker
	decMaker DecrypterMaker
}

// NewShadowSocksDialer get the dialer shadowsocks protocol
// if d == nil, the ssdialer will use default net dialer to
// establish the connection
func NewShadowSocksDialer(d Dialer, raddr, method, password string) Dialer {
	if d == nil {
		d = NewNetDialer()
	}
	return &ShadowSocksDialer{
		Dialer:   d,
		raddr:    raddr,
		encMaker: NewUtilsEncrypterMaker(method, password),
		decMaker: NewUtilsDecrypterMaker(method, password),
	}
}

func (d *ShadowSocksDialer) Dial(network, target string) (Conn, error) {
	conn, err := d.Dialer.Dial(network, d.raddr)
	if err != nil {
		return nil, err
	}
	conn = NewShadowSocksConn(conn, d.encMaker, d.decMaker)
	header := (&DstAddr{hostport: target}).Header()
	conn = NewRemainConn(conn, nil, header)
	return conn, nil
}

// PickFastestDialer would choose the fastest dialer
type PickFastDialer struct {
	dialers []Dialer
}

func NewPickFastDialer(dialers ...Dialer) Dialer {
	var p PickFastDialer
	for _, d := range dialers {
		p.dialers = append(p.dialers, d)
	}
	return &p
}

func (p *PickFastDialer) Dial(network, addr string) (Conn, error) {
	die := make(chan struct{})
	defer close(die)
	chErr := make(chan error, len(p.dialers))
	chConn := make(chan Conn)
	worker := func(d Dialer) {
		conn, err := d.Dial(network, addr)
		if err != nil {
			select {
			case <-die:
			case chErr <- err:
			}
			return
		}
		select {
		case <-die:
			conn.Close()
		case chConn <- conn:
		}
		return
	}
	for _, dialer := range p.dialers {
		go worker(dialer)
	}
	var err error
	for i := 0; i < len(p.dialers); i++ {
		select {
		case conn := <-chConn:
			return conn, nil
		case err = <-chErr:
		}
	}
	return nil, err
}

type AEADShadowSocksDialer struct {
	Dialer
	raddr    string
	encMaker *SSAeadEncrypterMaker
	decMaker *SSAeadDecrypterMaker
}

func NewAEADShadowSocksDialer(d Dialer, raddr, method, password string) Dialer {
	if d == nil {
		d = NewNetDialer()
	}
	return &AEADShadowSocksDialer{
		Dialer:   d,
		raddr:    raddr,
		encMaker: NewSSAeadEncrypterMaker(method, password),
		decMaker: NewSSAeadDecrypterMaker(method, password),
	}
}

func (d *AEADShadowSocksDialer) Dial(network, target string) (Conn, error) {
	conn, err := d.Dialer.Dial(network, d.raddr)
	if err != nil {
		return nil, err
	}
	conn = NewAEADShadowSocksConn(conn, d.encMaker, d.decMaker)
	header := (&DstAddr{hostport: target}).Header()
	conn = NewRemainConn(conn, nil, header)
	return conn, nil
}
