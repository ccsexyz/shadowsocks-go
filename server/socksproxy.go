package server

import (
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunSocksProxyServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, []ss.AcceptHandler{ss.LimitHandler, ss.SocksAcceptor}, socksProxyHandler)
}

func socksProxyHandler(ac *ss.AcceptedConn) {
	conn := ac.Conn
	c := ac.Config
	defer conn.Close()
	target := ac.TargetStr()
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

	rconn, err := ss.DialSSWithOptions(&ss.DialOptions{
		Target: target,
		C:      c,
		Data:   buf[:n],
	})
	utils.PutBuf(buf)
	if err != nil {
		c.Log(err)
		return
	}
	defer rconn.Close()
	c.Log("proxy", target, "from", conn.RemoteAddr(), "->", conn.LocalAddr(),
		"to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	ss.Pipe(conn, rconn, c)
}
