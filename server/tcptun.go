package server

import (
	"github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPTunServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, nil, tcpTunHandler)
}

func tcpTunHandler(ac *ss.AcceptedConn) {
	conn := ac.Conn
	c := ac.Config
	defer conn.Close()
	rconn, err := ss.DialSSWithOptions(&ss.DialOptions{
		Target: c.Remoteaddr,
		C:      c.Backend,
	})
	if err != nil {
		c.Log(err)
		return
	}
	defer rconn.Close()
	c.Log("tunnel", c.Remoteaddr, "from", conn.RemoteAddr(), "->", conn.LocalAddr(),
		"to", rconn.LocalAddr(), "->", rconn.RemoteAddr())
	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	ss.Pipe(conn, rconn, c)
}
