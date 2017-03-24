package main

import (
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunSSProxyServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSS, ssproxyHandler)
}

func ssproxyHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	C := conn.(*ss.DstConn).Conn.(*ss.RemainConn).Conn.(*ss.Conn)
	target := conn.(*ss.DstConn).GetDst()
	rconn, err := ss.DialMultiSS(target, c.Backends)
	if err != nil {
		return
	}
	defer rconn.Close()
	C.Xu0s() // FIXME
	c.Log("proxy", target, "to", rconn.RemoteAddr().String(), "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
