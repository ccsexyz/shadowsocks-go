package server

import (
	"net"
	"strings"

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
	if conn.GetCfg() != nil {
		c = conn.GetCfg()
	}
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

	// If the connection came from the SS fallback path (has an inner CryptoConn),
	// connect directly to the target like a server endpoint.
	if ss.HasCryptoConn(conn) {
		var rconn net.Conn
		if strings.HasPrefix(target, "ws://") || strings.HasPrefix(target, "wss://") {
			rconn, err = ss.DialWsConn(target, conn.GetHost(), c)
		} else {
			rconn, err = ss.DialTCP(target, c)
		}
		if err != nil {
			utils.PutBuf(buf)
			c.Log(err)
			return
		}
		defer rconn.Close()
		if n > 0 {
			rconn.Write(buf[:n])
		}
		utils.PutBuf(buf)
		c.Log("proxy", target, "from", conn.RemoteAddr(), "->", conn.LocalAddr(),
			"to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
		if c.LogHTTP {
			conn = ss.NewHttpLogConn(conn, c)
		}
		ss.Pipe(conn, rconn, c)
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
