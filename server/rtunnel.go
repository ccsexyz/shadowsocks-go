package server

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/xtaci/smux"
)

func RunRtunnelClient(c *ss.Config) {
	serverAddr := c.Backend.Remoteaddr
	targetAddr := c.Remoteaddr

	smuxConfig := smux.DefaultConfig()
	smuxConfig.KeepAliveInterval = time.Second

	backoff := 2 * time.Second
	const maxBackoff = 30 * time.Second

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
			select {
			case <-c.DieChan():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}

		backoff = 2 * time.Second

		session, err := smux.Client(rconn, smuxConfig)
		if err != nil {
			rconn.Close()
			select {
			case <-c.DieChan():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
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
				ss.Pipe(s, localConn, c)
			}(stream)
		}
		session.Close()
	}
}

func RunRtunnelServer(c *ss.Config) {
	if len(c.Backends) == 0 {
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
	for _, v := range c.Backends {
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

func rtunnelServerHandler(ac *ss.AcceptedConn) {
	conn := ac.Conn
	topCfg := ac.Config
	defer conn.Close()

	backendCfg := topCfg
	if cfg := conn.GetCfg(); cfg != nil {
		backendCfg = cfg
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
	session, err := smux.Server(conn, smuxConfig)
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
			ss.Pipe(client, s, backendCfg)
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

func ensureRtunnelBusyMap(c *ss.Config) *sync.Map {
	if m := c.InitRuntime().Any; m != nil {
		if sm, ok := m.(*sync.Map); ok {
			return sm
		}
	}
	sm := &sync.Map{}
	c.InitRuntime().Any = sm
	return sm
}
