package main

import (
	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/utils"
)

func RunTCPLocalServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, tcpLocalHandler)
}

func tcpLocalHandler(conn ss.Conn, c *ss.Config) {
	defer conn.Close()
	target := GetDstOfConn(conn)
	if len(target) == 0 {
		return
	}
	buf := utils.GetBuf(1024)
	n, err := conn.Read(buf)
	if err != nil {
		utils.PutBuf(buf)
		return
	}
	rconn, err := ss.DialSSWithOptions(ss.DialOptions{
		Target: target,
		C:      c,
		Data:   buf[:n],
	})
	utils.PutBuf(buf)
	if err != nil {
		c.Log("failed connect to", target, err)
		return
	}
	defer rconn.Close()
	c.Log("proxy", target, "from", conn.RemoteAddr(), "->",
		conn.LocalAddr(), "to", rconn.LocalAddr(), "->",
		rconn.RemoteAddr())
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
