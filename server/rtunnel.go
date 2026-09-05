package server

import (
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/xtaci/smux"
)

// Reconnect pacing for the rtunnel client. Failures escalate exponentially
// to rtunnelMaxBackoff; a session that stayed up for rtunnelSessionResetAfter
// (several server-side keepalive rounds) counts as healthy and resets the
// pace, so a server restart reconnects promptly while a server that accepts
// dials but rejects sessions is re-dialed at a widening interval instead of
// every base step.
const (
	rtunnelBackoffBase       = 2 * time.Second
	rtunnelMaxBackoff        = 30 * time.Second
	rtunnelSessionResetAfter = 30 * time.Second
)

// bumpBackoff doubles d, clamped to rtunnelMaxBackoff.
func bumpBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > rtunnelMaxBackoff {
		d = rtunnelMaxBackoff
	}
	return d
}

// nextReconnectBackoff folds a just-ended session's lifetime into the
// reconnect backoff: healthy sessions reset to the base pace, rapid ones
// escalate.
func nextReconnectBackoff(served, cur time.Duration) time.Duration {
	if served >= rtunnelSessionResetAfter {
		return rtunnelBackoffBase
	}
	return bumpBackoff(cur)
}

// rtunnelBackoffSleep waits d or until the config dies; reports whether the
// client should keep running.
func rtunnelBackoffSleep(c *ss.Config, d time.Duration) bool {
	select {
	case <-c.DieChan():
		return false
	case <-time.After(d):
		return true
	}
}

func RunRtunnelClient(c *ss.Config) {
	serverAddr := c.Backend.Remoteaddr
	targetAddr := c.Remoteaddr

	smuxConfig := smux.DefaultConfig()
	smuxConfig.KeepAliveInterval = time.Second

	backoff := rtunnelBackoffBase

	for {
		select {
		case <-c.DieChan():
			return
		default:
		}

		rconn, err := ss.DialSSWithOptions(&ss.DialOptions{
			Target: serverAddr,
			C:      c.Backend,
		})
		if err != nil {
			c.Log("rtunnel client: connect failed:", err, "- retry in", backoff)
			if !rtunnelBackoffSleep(c, backoff) {
				return
			}
			backoff = bumpBackoff(backoff)
			continue
		}

		started := time.Now()
		session, err := smux.Client(newIdleDeadlineRW(ss.AsReadWriteCloser(rconn, nil), rtunnelIdleTimeout), smuxConfig)
		if err != nil {
			rconn.Close()
			if !rtunnelBackoffSleep(c, backoff) {
				return
			}
			backoff = bumpBackoff(backoff)
			continue
		}

		for {
			stream, err := session.AcceptStream()
			if err != nil {
				break
			}
			go func(s *smux.Stream) {
				defer s.Close()
				localConn, err := ss.DialTCP(targetAddr, c)
				if err != nil {
					c.Log("rtunnel client: dial target failed:", err)
					return
				}
				defer localConn.Close()
				ss.Pipe(ss.AsNetConn(s), localConn, c)
			}(stream)
		}
		served := time.Since(started)
		session.Close()
		// Sleep before re-dialing even on the clean path: a server that
		// accepts the dial and then rejects or tears down the session right
		// away lands here with backoff still near its base, and without the
		// pause the client would re-dial at full speed forever. The lifetime
		// decides what comes next: healthy sessions reset the pace, rapid
		// ones escalate it.
		if !rtunnelBackoffSleep(c, backoff) {
			return
		}
		backoff = nextReconnectBackoff(served, backoff)
	}
}

func RunRtunnelServer(c *ss.Config) {
	if len(c.SnapshotBackends()) == 0 {
		runRtunnelSingleServer(c)
		return
	}
	runRtunnelMultiServer(c)
}

func runRtunnelSingleServer(c *ss.Config) {
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if c.Obfs {
		handlers = append(handlers, ss.ObfsHandler)
	}
	if crypto.IsAEAD2022(c.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}
	RunTCPServer(c.Localaddr, c, handlers, rtunnelServerHandler)
}

func runRtunnelMultiServer(c *ss.Config) {
	for _, v := range c.SnapshotBackends() {
		hits := 0
		v.InitRuntime().Any = &hits
	}
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if c.Obfs {
		handlers = append(handlers, ss.ObfsHandler)
	}
	handlers = append(handlers, ss.SSMultiHandler)
	RunTCPServer(c.Localaddr, c, handlers, rtunnelServerHandler)
}

func RtunnelHandler(ac *ss.AcceptedConn) { rtunnelServerHandler(ac) }

func rtunnelServerHandler(ac *ss.AcceptedConn) {
	conn := ac.Conn
	topCfg := ac.Config
	defer conn.Close()

	backendCfg := topCfg
	if cm, ok := conn.(ss.ConnMeta); ok {
		if cfg := cm.GetCfg(); cfg != nil {
			backendCfg = cfg
		}
	}

	serviceAddr := backendCfg.RtunnelService
	if serviceAddr == "" {
		backendCfg.Log("rtunnel server: no service address configured")
		return
	}

	busyMap := ensureRtunnelBusyMap(topCfg)

	if _, loaded := busyMap.LoadOrStore(backendCfg, true); loaded {
		backendCfg.Log("rtunnel server: backend already has active tunnel")
		return
	}
	defer busyMap.Delete(backendCfg)

	smuxConfig := smux.DefaultConfig()
	smuxConfig.KeepAliveInterval = 10 * time.Second
	session, err := smux.Server(newIdleDeadlineRW(ss.AsReadWriteCloser(conn, nil), rtunnelIdleTimeout), smuxConfig)
	if err != nil {
		backendCfg.Log("rtunnel server: smux session init failed:", err)
		return
	}
	defer session.Close()

	var ln net.Listener
	if strings.HasPrefix(serviceAddr, "@") {
		ln, err = ss.RegisterVirtual(serviceAddr, backendCfg.Nickname)
		if err != nil {
			backendCfg.Log("rtunnel server:", err)
			return
		}
		defer ss.UnregisterVirtual(serviceAddr)
	} else {
		ln, err = net.Listen("tcp", serviceAddr)
		if err != nil {
			backendCfg.Log("rtunnel server: service port listen failed:", err)
			return
		}
		defer ln.Close()
	}

	go notifySessionClose(session, topCfg, ln)

	backendCfg.Log("rtunnel server: service", serviceAddr, "ready")

	for {
		connA, err := ln.Accept()
		if err != nil {
			return
		}
		stream, err := session.OpenStream()
		if err != nil {
			connA.Close()
			return
		}
		go func(s *smux.Stream, client net.Conn) {
			defer s.Close()
			defer client.Close()
			ss.Pipe(ss.AsNetConn(client), ss.AsNetConn(s), backendCfg)
		}(stream, connA)
	}
}

func notifySessionClose(session *smux.Session, c *ss.Config, ln net.Listener) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.DieChan():
			ln.Close()
			return
		case <-ticker.C:
			if session.IsClosed() {
				ln.Close()
				return
			}
		}
	}
}

// rtunnelIdleTimeout bounds how long the smux receive loop may block without
// any inbound frame. smux keepalive is write-based: a peer that completes the
// SS handshake and then goes silent keeps "accepting" pings into its TCP send
// buffer, so without a read deadline the session — and with it the backend's
// rtunnel slot (busyMap) and the handler goroutine — is held forever, and
// every later rtunnel connection to that backend is rejected until restart.
// Both rtunnel ends run keepalive (client pings every 1s, server every 10s),
// so any healthy peer produces inbound frames far more often than this.
const rtunnelIdleTimeout = 60 * time.Second

// idleDeadlineRW re-arms a read deadline before every Read so the smux
// session dies when the peer stops producing frames. Reads are serialized
// (smux has a single recvLoop goroutine), so no coordination is needed.
type idleDeadlineRW struct {
	io.ReadWriteCloser
	idle time.Duration
}

func newIdleDeadlineRW(rwc io.ReadWriteCloser, idle time.Duration) *idleDeadlineRW {
	return &idleDeadlineRW{ReadWriteCloser: rwc, idle: idle}
}

func (r *idleDeadlineRW) Read(p []byte) (int, error) {
	if d, ok := r.ReadWriteCloser.(interface {
		SetReadDeadline(time.Time) error
	}); ok {
		d.SetReadDeadline(time.Now().Add(r.idle))
	}
	return r.ReadWriteCloser.Read(p)
}

var rtunnelBusyInitMu sync.Mutex

func ensureRtunnelBusyMap(c *ss.Config) *sync.Map {
	rtunnelBusyInitMu.Lock()
	defer rtunnelBusyInitMu.Unlock()
	if m := c.InitRuntime().Any; m != nil {
		if sm, ok := m.(*sync.Map); ok {
			return sm
		}
	}
	sm := &sync.Map{}
	c.InitRuntime().Any = sm
	return sm
}
