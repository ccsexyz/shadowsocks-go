package main

import (
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPTunServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenTCPTun, tcpTunHandler)
}

func tcpTunHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	rconn, err := ss.DialSS(c.Remoteaddr, c.Backend.Remoteaddr, c.Backend)
	if err != nil {
		c.Log(err)
		return
	}
	defer rconn.Close()
	c.Log("create tunnel from", conn.RemoteAddr().String(), "to", c.Remoteaddr, "through", rconn.RemoteAddr())
	ss.Pipe(conn, rconn)
}
