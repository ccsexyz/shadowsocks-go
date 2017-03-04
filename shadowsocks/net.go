package shadowsocks

import (
	"encoding/binary"
	"net"
	"strconv"
	"fmt"
	"io"
	"crypto/rand"
)

type sslistener struct {
	net.TCPListener
	c *Config
}

func (lis *sslistener) Accept() (conn net.Conn, err error) {
	conn, err = lis.TCPListener.Accept()
	if err != nil {
		return
	}
	conn = NewConn(conn, lis.c)
	return
}

func ListenSS(service string, c *Config) (lis net.Listener, err error) {
	addr, err := net.ResolveTCPAddr("tcp", service)
	if err != nil {
		return
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	lis = &sslistener{
		TCPListener: *l,
		c:           c,
	}
	return
}

func DialSS(target, service string, c *Config) (conn net.Conn, err error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return
	}
	portNum, err := strconv.Atoi(port)
	if err != nil {
		return
	}
	var buf [512]byte
	hostLen := len(host)
	headerLen := hostLen + 4
	buf[0] = typeDm
	buf[1] = byte(hostLen)
	copy(buf[2:], []byte(host))
	binary.BigEndian.PutUint16(buf[hostLen+2:], uint16(portNum))
	return DialSSWithRawHeader(buf[:headerLen], service, c)
}

func DialSSWithRawHeader(header []byte, service string, c *Config) (conn net.Conn, err error) {
	conn, err = net.Dial("tcp", service)
	if err != nil {
		return
	}
	conn = NewConn(conn, c)
	C := conn.(*Conn)
	buf := C.rbuf
	var n int
	if !c.Nonop {
		buf[0] = typeNop
		noplen := int(src.Int63() % 128)
		buf[1] = byte(noplen)
		binary.Read(rand.Reader, binary.BigEndian, buf[2:2+noplen])
		n = noplen + 2
	}
	copy(buf[n:], header)
	_, err = conn.Write(buf[:n+len(header)])
	if err != nil {
		conn.Close()
	}
	return
}

type socks5listener struct {
	net.TCPListener
	info *Config
	die    chan bool
	connch chan net.Conn
	err    error
}

func ListenSocks5(address string, c *Config) (lis net.Listener, err error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	lis = &socks5listener{
		TCPListener: *l,
		info:        c,
		die:         make(chan bool),
		connch:      make(chan net.Conn, 32),
	}
	go lis.(*socks5listener).acceptor()
	return
}

func (lis *socks5listener) Close() error {
	select {
	case <-lis.die:
	default:
		close(lis.die)
	}
	return lis.TCPListener.Close()
}

func (lis *socks5listener) Accept() (conn net.Conn, err error) {
	select {
	case <-lis.die:
		err = lis.err
		if err != nil {
			err = fmt.Errorf("cannot accept from closed listener")
		}
	case conn = <-lis.connch:
	}
	return
}

func (lis *socks5listener) acceptor() {
	defer lis.Close()
	for {
		conn, err := lis.TCPListener.Accept()
		if err != nil {
			lis.err = err
			return
		}
		go lis.handshake(conn)
	}
}

func (lis *socks5listener) handshake(conn net.Conn) {
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	buf := make([]byte, 512)
	_, err := io.ReadFull(conn, buf[:2])
	if err != nil || buf[0] != 5 {
		return
	}
	nmethods := buf[1]
	if nmethods != 0 {
		io.ReadFull(conn, buf[:int(nmethods)])
	}
	_, err = conn.Write([]byte{5, 0})
	if err != nil {
		return
	}
	select {
	case <-lis.die:
	case lis.connch <- conn:
		conn = nil
	}
	return
}

func NewTCPDialer() func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		return net.Dial("tcp", addr)
	}
}

func NewSSDialer(c *Config) func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		return DialSS(addr, c.Remoteaddr, c)
	}
}