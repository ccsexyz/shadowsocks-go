package server

import (
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPLocalServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, []ss.AcceptHandler{ss.LimitHandler, ss.SocksAcceptor}, tcpLocalHandler)
}

func tcpLocalHandler(ac *ss.AcceptedConn) {
	conn := ac.Conn
	c := ac.Config
	defer conn.Close()
	target := ac.TargetStr()
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	buf := utils.GetBuf(1024)
	n, err := conn.Read(buf)
	if err != nil {
		utils.PutBuf(buf)
		return
	}
	opt := &ss.DialOptions{
		Target: target,
		C:      c,
		Data:   buf[:n],
	}
	rconn, err := ss.DialSSWithOptions(opt)
	utils.PutBuf(buf)
	if err != nil {
		c.Log("failed connect to", target, err)
		return
	}
	defer rconn.Close()
	c.Log("proxy", opt.Target, "from", conn.RemoteAddr(), "->",
		conn.LocalAddr(), "to", rconn.LocalAddr(), "->",
		rconn.RemoteAddr())
	ss.Pipe(conn, rconn, c)
}
