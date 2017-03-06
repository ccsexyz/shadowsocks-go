package main

import (
	"fmt"
	"log"
	"net"

	"strconv"

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
		log.Fatal(err)
	}
	handle := func(sess *udpSession, b []byte) {
		host, _, data := ss.ParseAddr(b)
		if len(host) == 0 {
			return
		}
		sess.conn.Write(data)
	}
	create := func(b []byte) (rconn net.Conn, clean func(), header []byte, err error) {
		host, port, data := ss.ParseAddr(b)
		if len(host) == 0 {
			err = fmt.Errorf("unexpected header")
			return
		}
		target := net.JoinHostPort(host, strconv.Itoa(port))
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
	RunUDPServer(conn, nil, handle, create)
}

func RunUDPLocalServer(c *ss.Config) {
	conn, err := newUDPListener(c.Localaddr)
	if err != nil {
		log.Fatal(err)
	}
	check := func(b []byte) bool {
		if len(b) < 3 || b[2] != 0 || b[1] != 0 || b[0] != 0 {
			return false
		}
		return true
	}
	var handle func(*udpSession, []byte)
	var create func([]byte) (net.Conn, func(), []byte, error)
	if c.UDPOverTCP {
		handle = func(sess *udpSession, b []byte) {
			_, _, data := ss.ParseAddr(b[3:])
			sess.conn.Write(data)
		}
		create = func(b []byte) (rconn net.Conn, clean func(), header []byte, err error) {
			host, port, data := ss.ParseAddr(b[3:])
			if len(host) == 0 {
				err = fmt.Errorf("unexcepted header")
				return
			}
			rconn, err = ss.DialUDPOverTCP(net.JoinHostPort(host, strconv.Itoa(port)), c.Remoteaddr, c)
			if err != nil {
				return
			}
			rconn.Write(data)
			hdrlen := len(b) - len(data)
			header = make([]byte, hdrlen)
			copy(header, b)
			return
		}
	} else {
		handle = func(sess *udpSession, b []byte) {
			sess.conn.Write(b[3:])
		}
		create = func(b []byte) (rconn net.Conn, clean func(), header []byte, err error) {
			rconn, err = net.Dial("udp", c.Remoteaddr)
			if err != nil {
				return
			}
			rconn = ss.NewUDPConn(rconn.(*net.UDPConn), c)
			rconn.Write(b[3:])
			header = []byte{0, 0, 0}
			return
		}
	}

	RunUDPServer(conn, check, handle, create)
}
