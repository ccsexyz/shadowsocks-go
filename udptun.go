package main

import (
	"net"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func getCreateFuncOfUDPTunServer(c *ss.Config) func(*utils.SubConn) (net.Conn, net.Conn, error) {
	return func(conn *utils.SubConn) (c1, c2 net.Conn, err error) {
		rconn, err := ss.DialUDP(c.Backend)
		if err != nil {
			c.Log(err)
			return
		}
		buf := utils.GetBuf(512)
		defer utils.PutBuf(buf)
		addr, err := net.ResolveUDPAddr("udp", c.Remoteaddr)
		if err != nil {
			c.Logger.Fatal(err)
		}
		hdrlen := ss.PutHeader(buf, addr.IP.String(), addr.Port)
		header := buf[:hdrlen]
		c1 = newFECConn(rconn, c.Backend)
		c2 = &udpRemoteConn{Conn: conn, header: header}
		return
	}
}

func RunUDPTunServer(c *ss.Config) {
	listener, err := utils.NewUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	defer listener.Close()
	RunUDPServer(listener, c, getCreateFuncOfUDPTunServer)
}
