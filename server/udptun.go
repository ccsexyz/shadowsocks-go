package server

import (
	"net"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func getCreateFuncOfUDPTunServer(c *ss.Config, addr *net.UDPAddr) func(*utils.SubConn) (utils.Conn, utils.Conn, error) {
	return func(conn *utils.SubConn) (c1, c2 utils.Conn, err error) {
		rconn, err := ss.DialUDP(c.Backend)
		if err != nil {
			c.Log(err)
			return
		}
		buf := utils.GetBuf(512)
		defer utils.PutBuf(buf)
		hdrlen := ss.PutHeader(buf, addr.IP.String(), addr.Port)
		header := ss.DupBuffer(buf[:hdrlen])
		backendSip22 := crypto.IsAEAD2022(c.Backend.Method)
		// Requests entering a 2022 tunnel must be SIP022-wrapped: the bare
		// ATYP shape put here used to alias as a SIP022 header on the
		// backend and got packets silently dropped (e.g. DNS queries whose
		// first QNAME label length is 1 or 4 bytes).
		c1 = rconn
		if backendSip22 {
			c1 = &sip022RequestConn{Conn: rconn}
		}
		// Responses relayed back through writePayload use the remote's
		// format: 2022 servers wrap them in SIP022, legacy servers send
		// bare ATYP+addr+payload.
		c2 = &udpRemoteConn{Conn: conn, header: header, sip22: backendSip22}
		return
	}
}

func RunUDPTunServer(c *ss.Config) {
	listener, err := utils.NewUDPListener(c.Localaddr)
	if err != nil {
		c.InitRuntime().Logger.Fatal(err)
	}
	defer listener.Close()
	// Resolve once at startup: resolving per session let a transient DNS
	// failure Logger.Fatal the whole process on the first UDP packet.
	addr, err := net.ResolveUDPAddr("udp", c.Remoteaddr)
	if err != nil {
		c.InitRuntime().Logger.Fatal(err)
	}
	RunUDPServer(listener, c, func(cfg *ss.Config) func(*utils.SubConn) (utils.Conn, utils.Conn, error) {
		return getCreateFuncOfUDPTunServer(cfg, addr)
	})
}
