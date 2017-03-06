package main

import (
	"log"
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPLocalServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, tcpLocalHandler)
}

func tcpLocalHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	target := conn.(*ss.Conn3).Target.Addr
	rconn, err := ss.DialSS(target, c.Remoteaddr, c)
	if err != nil {
		return
	}
	defer rconn.Close()
	log.Println("connect to ", target, "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}

func RunTCPRedirServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenRedir, tcpLocalHandler)
}
