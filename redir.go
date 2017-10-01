package main

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/utils"
)

func RunTCPRedirServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenRedir, tcpLocalHandler)
}

type redirUDPLocalConn struct {
	net.Conn
}

func (conn *redirUDPLocalConn) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	if err != nil || n < 6 {
		return
	}
	n = copy(b, b[6:n])
	return
}

func getCreateFuncOfUDPRedirServer(c *ss.Config) func(*utils.SubConn) (net.Conn, net.Conn, error) {
	return func(conn *utils.SubConn) (c1, c2 net.Conn, err error) {
		buf := make([]byte, 2048)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, nil, err
		}
		if n < 6 {
			return nil, nil, fmt.Errorf("can't read orig dst")
		}
		rconn, err := ss.DialUDP(c)
		if err != nil {
			c.Log(err)
			return
		}
		hdrbuf := make([]byte, 512)
		hdrlen := ss.PutHeader(buf, net.IP(buf[:4]).String(), int(binary.BigEndian.Uint16(buf[4:6])))
		hdrbuf = ss.DupBuffer(hdrbuf[:hdrlen])
		_, err = rconn.Write(append(hdrbuf, buf[6:]...))
		if err != nil {
			rconn.Close()
			return
		}
		c1 = rconn
		c2 = &udpRemoteConn{Conn: &redirUDPLocalConn{Conn: conn}, header: hdrbuf}
		return
	}
}

func RunUDPRedirServer(c *ss.Config) {
	listener, err := utils.NewUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	defer listener.Close()
	tproxyListner, err := ss.NewUDPTProxyConn(listener)
	if err != nil {
		c.Logger.Fatal(err)
	}
	RunUDPServer(tproxyListner, c, getCreateFuncOfUDPRedirServer)
}
