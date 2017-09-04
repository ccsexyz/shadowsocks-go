package main

import (
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunMultiTCPRemoteServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenMultiSS, tcpRemoteHandler)
}

func RunTCPRemoteServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSS, tcpRemoteHandler)
}

func tcpRemoteHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	C, err := ss.GetSsConn(conn)
	if err != nil {
		c.LogD(err)
		return
	}
	if C.GetConfig() != nil {
		c = C.GetConfig()
	}
	dst, err := ss.GetDstConn(conn)
	if err != nil {
		c.LogD(err)
		return
	}
	target := dst.GetDst()
	if len(target) == 0 {
		c.LogD("target length is 0")
		return
	}
	rconn, err := net.Dial("tcp", target)
	if err != nil {
		c.Log(err)
		return
	}
	defer rconn.Close()
	C.Xu0s()
	c.Log("connect to", target, "from", conn.RemoteAddr().String())
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	ss.Pipe(conn, rconn, c)
}
