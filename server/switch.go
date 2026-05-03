package server

import (
	"net"
	"strings"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunSwitchServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, nil, switchHandler)
}

func findActiveBackend(c *ss.Config) *ss.Config {
	for _, b := range c.Backends {
		if b.Nickname == c.ActiveBackend {
			return b
		}
	}
	return nil
}

func switchHandler(ac *ss.AcceptedConn) {
	conn := ac.Conn
	c := ac.Config
	defer conn.Close()

	backend := findActiveBackend(c)
	if backend == nil {
		c.Log("switch: active backend not found:", c.ActiveBackend)
		return
	}

	var rconn net.Conn
	var err error

	if backend.Target != "" {
		target := backend.Target
		if !strings.HasPrefix(target, "@") {
			target = "@" + target
		}
		rconn, err = ss.DialVirtual(target)
		if err != nil && !strings.HasPrefix(backend.Target, "@") {
			rconn, err = net.Dial("tcp", backend.Target)
		}
	} else if backend.Method != "" && backend.Method != "plain" {
		target := backend.Forward
		if target == "" {
			target = backend.Remoteaddr
		}
		rconn, err = ss.DialSSWithOptions(&ss.DialOptions{
			Target: target,
			C:      backend,
		})
	} else {
		rconn, err = net.Dial("tcp", backend.Remoteaddr)
	}

	if err != nil {
		c.Log("switch: dial error:", err)
		return
	}
	defer rconn.Close()

	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	c.Log("switch:", c.ActiveBackend, "from", conn.RemoteAddr(), "to", rconn.RemoteAddr())
	ss.Pipe(conn, rconn, c)
}
