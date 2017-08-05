package main

import (
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunSocksProxyServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, socksProxyHandler)
}

func socksProxyHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	dst, err := ss.GetDstConn(conn)
	if err != nil {
		return
	}
	target := dst.GetDst()
	rconn, err := ss.DialMultiSS(target, c.Backends)
	if err != nil {
		c.Log(err)
		return
	}
	defer rconn.Close()
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	c.Log("proxy", target, "to", rconn.RemoteAddr().String(), "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
