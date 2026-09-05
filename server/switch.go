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
	// activeBackend() reads under adminWriteMu: the admin API rewrites the
	// field at runtime and a torn string-header read would be memory-unsafe.
	active := c.GetActiveBackend()
	for _, b := range c.SnapshotBackends() {
		if b.Nickname == active {
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
		c.Log("switch: active backend not found:", c.GetActiveBackend())
		return
	}

	var rconn ss.Conn
	var err error

	if backend.Target != "" {
		target := backend.Target
		if !strings.HasPrefix(target, "@") {
			target = "@" + target
		}
		var nc net.Conn
		nc, err = ss.DialVirtual(target)
		if err != nil && !strings.HasPrefix(backend.Target, "@") {
			nc, err = net.Dial("tcp", backend.Target)
		}
		if err == nil {
			rconn = ss.AsNetConn(nc)
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
		var nc net.Conn
		nc, err = net.Dial("tcp", backend.Remoteaddr)
		if err == nil {
			rconn = ss.AsNetConn(nc)
		}
	}

	if err != nil {
		c.Log("switch: dial error:", err)
		return
	}
	defer rconn.Close()

	if c.LogHTTP {
		conn = ss.NewHttpLogConn(conn, c)
	}
	c.Log("switch:", c.GetActiveBackend(), "from", conn.RemoteAddr(), "to", rconn.RemoteAddr())
	ss.Pipe(conn, rconn, c)
}
