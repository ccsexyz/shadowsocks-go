package main

import (
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"net"
	"log"
)

func RunTCPServer(address string, c *ss.Config,
		listen func(string, *ss.Config)(net.Listener, error),
		handler func(net.Conn, *ss.Config)) {
	ss.CheckConfig(c)
	lis, err := listen(address, c)
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go handler(conn, c)
	}
}