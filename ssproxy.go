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
	C := conn.(*ss.Conn)
	target := C.Target
	rconn, err := ss.DialMultiSS(target.Addr, c.Backends)
	if err != nil {
		return
	}
	defer rconn.Close()
	C.Xu0s() // FIXME
	if len(target.Remain) != 0 {
		_, err := rconn.Write(target.Remain)
		if err != nil {
			c.Log(err)
			return
		}
	}
	c.Log("proxy", target.Addr, "to", rconn.RemoteAddr().String(), "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
