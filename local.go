package main

import (
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPLocalServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, tcpLocalHandler)
}

// type HttpRequestLogConn struct {
// 	net.Conn
// }

func tcpLocalHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	dst, err := ss.GetDstConn(conn)
	if err != nil {
		return
	}
	target := dst.GetDst()
	rconn, err := ss.DialSS(target, c.Remoteaddr, c)
	if err != nil {
		c.Log("failed connect to", target, err)
		return
	}
	defer rconn.Close()
	c.Log("connect to ", target, "from", conn.RemoteAddr().String())
	// lim, err := ss.GetLimitConn(conn)
	// if err == nil {
	// 	defer func() {
	// 		for _, v := range lim.Rlimiters {
	// 			c.Log("read", v.GetTotalBytes(), "bytes")
	// 		}
	// 		for _, v := range lim.Wlimiters {
	// 			c.Log("write", v.GetTotalBytes(), "bytes")
	// 		}
	// 	}()
	// }
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	ss.Pipe(conn, rconn, c)
}

func RunTCPRedirServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenRedir, tcpLocalHandler)
}
