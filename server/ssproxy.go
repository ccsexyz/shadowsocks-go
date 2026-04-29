package server

import (
	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunSSProxyServer(c *ss.Config) {
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if c.Obfs {
		handlers = append(handlers, ss.ObfsHandler)
	}
	if crypto.IsAEAD2022(c.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}
	RunTCPServer(c.Localaddr, c, handlers, ssproxyHandler)
}

func SSProxyHandler(ac *ss.AcceptedConn) { ssproxyHandler(ac) }

func ssproxyHandler(ac *ss.AcceptedConn) {
	conn := ac.Conn
	c := ac.Config
	defer conn.Close()
	C, err := ss.GetSsConn(conn)
	if err != nil {
		c.LogD(err)
	}
	target := ac.TargetStr()
	if len(target) == 0 {
		c.LogD("target length is 0")
		return
	}
	buf := utils.GetBuf(1024)
	n, err := conn.Read(buf)
	if err != nil {
		c.Log(err)
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
	if C != nil {
		C.CancelDeferClose()
	}
	c.Log("proxy", target, "from", conn.RemoteAddr(), "->", conn.LocalAddr(),
		"to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	ss.Pipe(conn, rconn, c)
}
