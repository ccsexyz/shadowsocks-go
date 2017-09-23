package main

import (
	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPTunServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenTCPTun, tcpTunHandler)
}

func tcpTunHandler(conn ss.Conn, c *ss.Config) {
	defer conn.Close()
	rconn, err := ss.DialSS(c.Remoteaddr, c.Backend)
	if err != nil {
		c.Log(err)
		return
	}
	defer rconn.Close()
	c.Log("tunnel", c.Remoteaddr, "from", conn.RemoteAddr(), "->", conn.LocalAddr(),
		"to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	ss.Pipe(conn, rconn, c)
}
