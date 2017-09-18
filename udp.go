package main

import (
	"fmt"
	"math/rand"
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/utils"
)

func getDefaultUDPServerCtx() *utils.UDPServerCtx {
	return &utils.UDPServerCtx{Mtu: 2048, Expires: 60}
}

type udpLocalConn struct {
	net.Conn
}

func (conn *udpLocalConn) Read(b []byte) (n int, err error) {
	if len(b) < 3 {
		err = fmt.Errorf("the length of buffer can't be less than three")
		return
	}
	b[0] = 0
	b[1] = 0
	b[2] = 0
	n, err = conn.Read(b[3:])
	n += 3
	return
}

func (conn *udpLocalConn) Write(b []byte) (n int, err error) {
	if len(b) < 3 {
		err = fmt.Errorf("the length of buffer can't be less than three")
		return
	}
	n, err = conn.Conn.Write(b[3:])
	n += 3
	return
}

type udpRemoteConn struct {
	net.Conn
	header []byte
}

func (conn *udpRemoteConn) Read(b []byte) (n int, err error) {
	hdrlen := len(conn.header)
	if len(b) < hdrlen {
		err = fmt.Errorf("the length of buffer can't be less than hdrlen %d", hdrlen)
		return
	}
	n, err = conn.Conn.Read(b[hdrlen:])
	if err != nil {
		return
	}
	if hdrlen > 0 {
		copy(b, conn.header)
		n += hdrlen
	}
	return
}

func (conn *udpRemoteConn) Write(b []byte) (n int, err error) {
	_, data, err := ss.ParseAddr(b)
	if err != nil {
		return
	}
	n, err = conn.Conn.Write(data)
	if err != nil {
		return
	}
	n += len(b) - len(data)
	return
}

func getCreateFuncOfUDPRemoteServer(c *ss.Config) func(*utils.SubConn) (net.Conn, net.Conn, error) {
	return func(conn *utils.SubConn) (c1, c2 net.Conn, err error) {
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		b := buf[:n]
		addr, data, err := ss.ParseAddr(b)
		if err != nil {
			err = fmt.Errorf("unexpected header")
			return
		}
		var rconn net.Conn
		if len(c.Backends) != 0 && c.Type == "ssproxy" {
			v := c.Backends[rand.Int()%len(c.Backends)]
			rconn, err = ss.DialUDP(v)
			if err != nil {
				return
			}
			rconn.Write(b)
			c1 = conn
			c2 = rconn
			return
		}
		target := net.JoinHostPort(addr.Host(), addr.Port())
		rconn, err = net.Dial("udp", target)
		if err != nil {
			c.LogD(err)
			return
		}
		rconn.Write(data)
		c1 = conn
		c2 = &udpRemoteConn{
			Conn:   rconn,
			header: ss.DupBuffer(b[:len(b)-len(data)]),
		}
		return
	}
}

func RunUDPRemoteServer(c *ss.Config) {
	conn, err := utils.NewUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	getDefaultUDPServerCtx().
		RunUDPServer(ss.NewUDPConn(conn, c),
			getCreateFuncOfUDPRemoteServer(c))
}

func RunMultiUDPRemoteServer(c *ss.Config) {
	listener, err := utils.NewUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	getDefaultUDPServerCtx().
		RunUDPServer(ss.NewMultiUDPConn(listener, c),
			getCreateFuncOfUDPRemoteServer(c))
}

func getCreateFuncOfUDPLocalServer(c *ss.Config) func(*utils.SubConn) (net.Conn, net.Conn, error) {
	return func(conn *utils.SubConn) (c1, c2 net.Conn, err error) {
		var subconfig *ss.Config
		if len(c.Backends) != 0 && c.Type == "socksproxy" {
			subconfig = c.Backends[rand.Int()%len(c.Backends)]
		} else {
			subconfig = c
		}
		rconn, err := ss.DialUDP(subconfig)
		if err != nil {
			return
		}
		c1 = conn
		c2 = rconn
		return
	}
}

func RunUDPLocalServer(c *ss.Config) {
	listener, err := utils.NewUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	getDefaultUDPServerCtx().RunUDPServer(listener, getCreateFuncOfUDPLocalServer(c))
}
