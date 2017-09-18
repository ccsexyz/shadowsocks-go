package main

import (
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/utils"
)

func RunTCPServer(address string, c *ss.Config,
	listen func(string, *ss.Config) (net.Listener, error),
	handler func(ss.Conn, *ss.Config)) {
	lis, err := listen(address, c)
	if err != nil {
		c.Logger.Fatal(err)
	}
	defer lis.Close()
	go func() {
		if c.Die != nil {
			<-c.Die
			lis.Close()
		}
	}()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go handler(conn.(ss.Conn), c)
	}
}

func GetDstOfConn(conn ss.Conn) string {
	dst := conn.GetDst()
	if dst == nil {
		return ""
	}
	return dst.String()
}

func getDefaultUDPServerCtx() *utils.UDPServerCtx {
	return &utils.UDPServerCtx{Mtu: 2048, Expires: 60}
}

func RunUDPServer(listener net.PacketConn, config *ss.Config, creator func(*ss.Config) func(*utils.SubConn) (net.Conn, net.Conn, error)) {
	go func() {
		if config.Die == nil {
			return
		}
		defer listener.Close()
		<-config.Die
	}()
	getDefaultUDPServerCtx().RunUDPServer(listener, creator(config))
}
