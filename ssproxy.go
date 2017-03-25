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
	C, err := ss.GetConn(conn)
	if err != nil {
		return
	}
	dst, err := ss.GetDstConn(conn)
	if err != nil {
		return
	}
	target := dst.GetDst()
	if len(target) == 0 {
		c.LogD("target length is 0")
		return
	}
	rconn, err := ss.DialMultiSS(target, c.Backends)
	if err != nil {
		return
	}
	defer rconn.Close()
	C.Xu0s() // FIXME
	c.Log("proxy", target, "to", rconn.RemoteAddr().String(), "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
