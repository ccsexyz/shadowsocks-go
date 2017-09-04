package main

import (
	"fmt"
	"math/rand"
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

type relaySession struct {
	conn   net.Conn
	live   bool
	from   *net.UDPAddr
	die    chan bool
	header []byte
}

func (sess *relaySession) Close() {
	select {
	case <-sess.die:
	default:
		sess.conn.Close()
		close(sess.die)
	}
}

func newUDPListener(address string) (conn *net.UDPConn, err error) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err == nil {
		conn, err = net.ListenUDP("udp", laddr)
	}
	return
}

func RunUDPRemoteServer(c *ss.Config) {
	conn, err := newUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	var pconn net.PacketConn
	pconn = ss.NewUDPConn(conn, c)
	handle := func(sess *udpSession, b []byte) {
		if len(c.Backends) != 0 && c.Type == "ssproxy" {
			sess.conn.Write(b)
			return
		}
		_, data, err := ss.ParseAddr(b)
		if err != nil {
			return
		}
		sess.conn.Write(data)
	}
	create := func(b []byte, from net.Addr) (rconn net.Conn, clean func(), header []byte, err error) {
		addr, data, err := ss.ParseAddr(b)
		if err != nil {
			err = fmt.Errorf("unexpected header")
			return
		}
		if len(c.Backends) != 0 && c.Type == "ssproxy" {
			v := c.Backends[rand.Int()%len(c.Backends)]
			rconn, err = ss.DialUDP(v)
			if err != nil {
				return
			}
			rconn.Write(b)
			return
		}
		target := net.JoinHostPort(addr.Host(), addr.Port())
		rconn, err = net.Dial("udp", target)
		if err != nil {
			return
		}
		hdrlen := len(b) - len(data)
		header = make([]byte, hdrlen)
		copy(header, b)
		rconn.Write(data)
		return
	}
	RunUDPServer(pconn, c, nil, handle, create)
}

func RunMultiUDPRemoteServer(c *ss.Config) {
	conn, err := newUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	mconn := ss.NewMultiUDPConn(conn, c)
	handle := func(sess *udpSession, b []byte) {
		_, data, err := ss.ParseAddr(b)
		if err != nil {
			return
		}
		sess.conn.Write(data)
	}
	create := func(b []byte, from net.Addr) (rconn net.Conn, clean func(), header []byte, err error) {
		addr, data, err := ss.ParseAddr(b)
		if err != nil {
			err = fmt.Errorf("unexpected header")
			return
		}
		target := net.JoinHostPort(addr.Host(), addr.Port())
		rconn, err = net.Dial("udp", target)
		if err != nil {
			c.LogD(err)
			return
		}
		hdrlen := len(b) - len(data)
		header = make([]byte, hdrlen)
		copy(header, b)
		rconn.Write(data)
		clean = func() {
			mconn.RemoveAddr(from)
		}
		return
	}
	RunUDPServer(mconn, c, nil, handle, create)
}

func RunUDPLocalServer(c *ss.Config) {
	conn, err := newUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	check := func(b []byte) bool {
		if len(b) < 3 || b[2] != 0 || b[1] != 0 || b[0] != 0 {
			return false
		}
		return true
	}
	var handle func(*udpSession, []byte)
	var create func([]byte, net.Addr) (net.Conn, func(), []byte, error)
	handle = func(sess *udpSession, b []byte) {
		sess.conn.Write(b[3:])
	}
	create = func(b []byte, from net.Addr) (rconn net.Conn, clean func(), header []byte, err error) {
		var v *ss.Config
		if len(c.Backends) != 0 && c.Type == "socksproxy" {
			v = c.Backends[rand.Int()%len(c.Backends)]
		} else {
			v = c
		}
		rconn, err = ss.DialUDP(v)
		if err != nil {
			return
		}
		rconn.Write(b[3:])
		header = []byte{0, 0, 0}
		return
	}

	RunUDPServer(conn, c, check, handle, create)
}
