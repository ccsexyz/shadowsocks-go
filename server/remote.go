package server

import (
	"strings"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// netConnAdapter wraps an ss.Conn to implement net.Conn for TrackOutbound.
type netConnAdapter struct {
	ss.Conn
}

func (a *netConnAdapter) Read(b []byte) (int, error) {
	return ss.ReadN(a.Conn, b, nil)
}

func (a *netConnAdapter) Write(b []byte) (int, error) {
	return a.Conn.Write(b)
}

func RunMultiTCPRemoteServer(c *ss.Config) {
	for _, v := range c.SnapshotBackends() {
		hits := 0
		v.InitRuntime().Any = &hits
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

func RemoteHandler(ac *ss.AcceptedConn) { tcpRemoteHandler(ac) }

func tcpRemoteHandler(ac *ss.AcceptedConn) {
	conn := ac.Conn
	c := ac.Config
	defer conn.Close()
	C, err := ss.GetSsConn(conn)
	if err != nil {
		// Without the inner ss conn, CancelDeferClose below can't run and
		// the FIN-linger stays active; log the cause instead of dropping it.
		c.Log("get ss conn failed:", err)
		C = nil
	}
	if cm, ok := conn.(ss.ConnMeta); ok {
		if cfg := cm.GetCfg(); cfg != nil {
			c = cfg
		}
	}
	target := ac.TargetStr()
	if len(target) == 0 {
		c.LogD("target length is 0")
		return
	}
	var rconn ss.Conn
	host := ""
	if cm, ok := conn.(ss.ConnMeta); ok {
		host = cm.GetHost()
	}
	if strings.HasPrefix(target, "ws://") || strings.HasPrefix(target, "wss://") {
		rconn, err = ss.DialWsConn(target, host, c)
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
				nca := &netConnAdapter{Conn: rconn}
				rconn = ss.AsNetConn(tracker.TrackOutbound(nca, rec, target))
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
