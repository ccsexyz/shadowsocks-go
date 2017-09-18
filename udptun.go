package main

import (
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/utils"
)

func getCreateFuncOfUDPTunServer(c *ss.Config) func(*utils.SubConn) (net.Conn, net.Conn, error) {
	return func(conn *utils.SubConn) (c1, c2 net.Conn, err error) {
		rconn, err := ss.DialUDP(c.Backend)
		if err != nil {
			return
		}
		buf := make([]byte, 512)
		addr, err := net.ResolveUDPAddr("udp", c.Remoteaddr)
		if err != nil {
			c.Logger.Fatal(err)
		}
		hdrlen := ss.PutHeader(buf, addr.IP.String(), addr.Port)
		header := buf[:hdrlen]
		c1 = conn
		c2 = &udpRemoteConn{Conn: rconn, header: header}
		return
	}
}

func RunUDPTunServer(c *ss.Config) {
	listener, err := utils.NewUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	defer listener.Close()
	getDefaultUDPServerCtx().
		RunUDPServer(listener,
			getCreateFuncOfUDPTunServer(c))
}
