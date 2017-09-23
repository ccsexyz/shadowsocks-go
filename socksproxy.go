package main

import (
	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunSocksProxyServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, socksProxyHandler)
}

func socksProxyHandler(conn ss.Conn, c *ss.Config) {
	defer conn.Close()
	target := GetDstOfConn(conn)
	if len(target) == 0 {
		return
	}
	rconn, err := ss.DialSS(target, c)
	if err != nil {
		c.Log(err)
		return
	}
	defer rconn.Close()
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	c.Log("proxy", target, "from", conn.RemoteAddr(), "->", conn.LocalAddr(),
		"to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
	ss.Pipe(conn, rconn, c)
}
