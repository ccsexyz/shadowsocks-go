package main

import (
	"log"
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPRemoteServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSS, tcpRemoteHandler)
}

func tcpRemoteHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	C := conn.(*ss.Conn)
	target := C.Target
	if len(target.Addr) == 0 {
		return
	}
	rconn, err := net.Dial("tcp", target.Addr)
	if err != nil {
		log.Println(err)
		return
	}
	defer rconn.Close()
	if C != nil {
		C.Xu0s()
	}
	if len(target.Remain) != 0 {
		_, err = rconn.Write(target.Remain)
		if err != nil {
			log.Println(err)
			return
		}
	}
	log.Println("connect to", target.Addr, "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
