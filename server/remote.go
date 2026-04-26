package server

import (
	"net"
	"strings"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunMultiTCPRemoteServer(c *ss.Config) {
	for _, v := range c.Backends {
		hits := 0
		v.Any = &hits
	}
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if c.Obfs {
		handlers = append(handlers, ss.ObfsHandler)
	}
	handlers = append(handlers, ss.SSMultiHandler)
	RunTCPServer(c.Localaddr, c, handlers, tcpRemoteHandler)
}

func RunTCPRemoteServer(c *ss.Config) {
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if c.Obfs {
		handlers = append(handlers, ss.ObfsHandler)
	}
	if crypto.IsAEAD2022(c.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}
	RunTCPServer(c.Localaddr, c, handlers, tcpRemoteHandler)
}

func RunWstunnelRemoteServer(c *ss.Config) {
	RunTCPRemoteServer(c)
}

func tcpRemoteHandler(ac *ss.AcceptedConn) {
	conn := ac.Conn
	c := ac.Config
	defer conn.Close()
	C, err := ss.GetSsConn(conn)
	if err != nil {
		C = nil
	}
	if conn.GetCfg() != nil {
		c = conn.GetCfg()
	}
	target := ac.TargetStr()
	if len(target) == 0 {
		c.LogD("target length is 0")
		return
	}
	var rconn net.Conn
	if strings.HasPrefix(target, "ws://") || strings.HasPrefix(target, "wss://") {
		rconn, err = ss.DialWsConn(target, conn.GetHost(), c)
	} else {
		rconn, err = ss.DialTCP(target, c)
	}
	if err != nil {
		c.Log(err)
		return
	}
	// wrap outbound conn with tracking, paired to the inbound connection
	if sc, ok := conn.(*ss.StatConn); ok {
		if rec := sc.GetRecord(); rec != nil {
			if tracker := c.GetTracker(); tracker != nil {
				rconn = tracker.TrackOutbound(rconn, rec, target)
			}
		}
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
