package main

import (
	"log"
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunSocksProxyServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, socksProxyHandler)
}

func socksProxyHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	target := conn.(*ss.Conn3).Target.Addr
	rconn, err := ss.DialMultiSS(target, c.Backends)
	if err != nil {
		log.Println(err)
		return
	}
	defer rconn.Close()
	log.Println("proxy", target, "to", rconn.RemoteAddr().String(), "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
