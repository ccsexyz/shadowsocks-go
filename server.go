package main

import (
	"net"

	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunMultiTCPRemoteServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenMultiSS, tcpRemoteHandler)
}

func RunTCPRemoteServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSS, tcpRemoteHandler)
}

func tcpRemoteHandler(conn ss.Conn, c *ss.Config) {
	defer conn.Close()
	C, err := ss.GetSsConn(conn)
	if err != nil {
		C = nil
	}
	if conn.GetCfg() != nil {
		c = conn.GetCfg()
	}
	target := GetDstOfConn(conn)
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
	if C != nil {
		C.Xu0s()
	}
	c.Log("proxy", target, "from", conn.RemoteAddr(), "->", conn.LocalAddr(),
		"to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	ss.Pipe(conn, rconn, c)
}
