package main

import (
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPLocalServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, tcpLocalHandler)
}

func tcpLocalHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	dst, err := ss.GetDstConn(conn)
	if err != nil {
		return
	}
	target := dst.GetDst()
	rconn, err := ss.DialSS(target, c.Remoteaddr, c)
	if err != nil {
		c.Log("failed connect to", target, err)
		return
	}
	defer rconn.Close()
	c.Log("connect to ", target, "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}

func RunTCPRedirServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenRedir, tcpLocalHandler)
}
