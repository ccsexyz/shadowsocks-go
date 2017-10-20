package main

import (
	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/ccsexyz/utils"
)

func RunSSProxyServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSS, ssproxyHandler)
}

func ssproxyHandler(conn ss.Conn, c *ss.Config) {
	defer conn.Close()
	C, err := ss.GetSsConn(conn)
	if err != nil {
		return
	}
	target := GetDstOfConn(conn)
	if len(target) == 0 {
		c.LogD("target length is 0")
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
		return
	}
	defer rconn.Close()
	C.Xu0s() // FIXME
	c.Log("proxy", target, "from", conn.RemoteAddr(), "->", conn.LocalAddr(),
		"to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
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
