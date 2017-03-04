package main

import (
	"net"
	"log"
	"strconv"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPLocalServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, tcpLocalHandler)
}

func tcpLocalHandler(conn net.Conn, c *ss.Config)  {
	defer conn.Close()
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	if buf[0] != 5 || buf[1] != 1 {
		return
	}
	buf = buf[3:n]
	host, port, _ := ss.ParseAddr(buf)
	if len(host) == 0 {
		return
	}
	rconn, err := ss.DialSS(net.JoinHostPort(host, strconv.Itoa(port)), c.Remoteaddr, c)
	if err != nil {
		return
	}
	defer rconn.Close()
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return
	}
	log.Println("connect to ", host, port, "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}