package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand/v2"
	"net"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

type udpLocalConn struct {
	net.Conn
}

func (conn *udpLocalConn) Read(b []byte) (n int, err error) {
	if len(b) < 3 {
		err = fmt.Errorf("the length of buffer can't be less than three")
		return
	}
	// Read SIP022-format response from SS tunnel: [Type][TS][PadLen][Pad][Addr][Port][Payload]
	n, err = conn.Conn.Read(b[3:])
	if err != nil {
		return
	}
	// Parse SIP022 and convert to SOCKS5: [RSV(2)][FRAG(1)][ATYP(1)][ADDR][PORT(2)][PAYLOAD]
	hdr, host, port, payload, perr := crypto.ParseSIP022(b[3 : 3+n])
	if perr != nil {
		// Not SIP022 — pass through as-is (compat with old format)
		_ = hdr
		b[0] = 0
		b[1] = 0
		b[2] = 0
		return n + 3, nil
	}
	return crypto.BuildSOCKS5Response(b, host, port, payload), nil
}

func (conn *udpLocalConn) Write(b []byte) (n int, err error) {
	if len(b) < 3 {
		err = fmt.Errorf("the length of buffer can't be less than three")
		return
	}
	// Convert SOCKS5 to SIP022 format, then write to SS tunnel
	sipPkt := crypto.BuildSIP022Request(b[3:])
	_, err = conn.Conn.Write(sipPkt)
	if err != nil {
		return
	}
	return len(b), nil
}

type udpRemoteConn struct {
	net.Conn
	header []byte // SIP022 header: [Type][TS][PadLen][Pad][Addr][Port]
}

func (conn *udpRemoteConn) Read(b []byte) (n int, err error) {
	hdrlen := len(conn.header)
	if len(b) < hdrlen {
		err = fmt.Errorf("the length of buffer can't be less than hdrlen %d", hdrlen)
		return
	}
	// Read payload from target, prepend stored SIP022 header
	n, err = conn.Conn.Read(b[hdrlen:])
	if err != nil {
		return
	}
	if hdrlen > 0 {
		copy(b, conn.header)
		n += hdrlen
	}
	return
}

func (conn *udpRemoteConn) Write(b []byte) (n int, err error) {
	// Try SIP022 format first, then fall back to legacy ATYP format
	_, _, _, payload, perr := crypto.ParseSIP022(b)
	if perr != nil {
		_, payload, err = ss.ParseAddr(b)
		if err != nil {
			log.Printf("[UDP] remote Write: parse failed: %v", err)
			return
		}
	}
	_, err = conn.Conn.Write(payload)
	if err != nil {
		return
	}
	return len(b), nil
}

func getCreateFuncOfUDPRemoteServer(c *ss.Config) func(*utils.SubConn) (net.Conn, net.Conn, error) {
	return func(subconn *utils.SubConn) (c1, c2 net.Conn, err error) {
		conn := newFECConn(subconn, c)
		buf := utils.GetBuf(2048)
		defer utils.PutBuf(buf)
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("udp remote handler: SubConn.Read failed: %v", err)
			return
		}
		b := buf[:n]

		// Try SIP022 format first, fall back to legacy ATYP format
		sipHdr, host, port, data, perr := crypto.ParseSIP022(b)
		if perr == nil {
			// SIP022 parsed: build response header with Type=1 (SERVER), ClientSID=0
			sipHdr = crypto.BuildSIP022Response(makeATYPHeader(host, port), 0)
		} else {
			// Legacy format: [ATYP][ADDR][PORT][PAYLOAD]
			var addr *ss.SockAddr
			addr, data, perr = ss.ParseAddr(b)
			if perr != nil {
				log.Printf("udp remote handler: parse failed len=%d firstByte=0x%02x err=%v", n, b[0], perr)
				return
			}
			host = addr.Host()
			port, _ = strconvAddrPort(addr.Port())
			sipHdr = b[:len(b)-len(data)] // legacy header: ATYP+ADDR+PORT
		}

		target := net.JoinHostPort(host, portStr(port))

		var rconn net.Conn
		if len(c.Backends) != 0 && c.Type == "ssproxy" {
			v := c.Backends[rand.Int()%len(c.Backends)]
			rconn, err = ss.DialUDP(v)
			if err != nil {
				return
			}
			rconn.Write(b)
			c1 = conn
			c2 = rconn
			return
		}
		rconn, err = net.Dial("udp", target)
		if err != nil {
			log.Printf("udp remote handler: dial target %s failed: %v", target, err)
			return
		}
		_, err = rconn.Write(data)
		if err != nil {
			log.Printf("udp remote handler: write to target %s failed: %v", target, err)
			return
		}
		c1 = conn
		c2 = &udpRemoteConn{
			Conn:   rconn,
			header: ss.DupBuffer(sipHdr),
		}
		return
	}
}

// makeATYPHeader builds an ATYP+ADDR+PORT header for the given host and port.
func makeATYPHeader(host string, port int) []byte {
	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		hdr := make([]byte, 1+4+2)
		hdr[0] = 1 // ATYP IPv4
		copy(hdr[1:5], ip4)
		binary.BigEndian.PutUint16(hdr[5:7], uint16(port))
		return hdr
	}
	// Domain
	hdr := make([]byte, 1+1+len(host)+2)
	hdr[0] = 3 // ATYP Domain
	hdr[1] = byte(len(host))
	copy(hdr[2:], host)
	binary.BigEndian.PutUint16(hdr[2+len(host):], uint16(port))
	return hdr
}

func strconvAddrPort(s string) (int, error) {
	var p int
	_, err := fmt.Sscanf(s, "%d", &p)
	return p, err
}

func portStr(port int) string { return fmt.Sprintf("%d", port) }

func RunUDPRemoteServer(c *ss.Config) {
	lis, err := ss.ListenUDP(c)
	if err != nil {
		c.InitRuntime().Logger.Fatal(err)
	}
	defer lis.Close()
	RunUDPServer(lis, c, getCreateFuncOfUDPRemoteServer)
}

func RunMultiUDPRemoteServer(c *ss.Config) {
	lis, err := ss.ListenMultiUDP(c)
	if err != nil {
		c.InitRuntime().Logger.Fatal(err)
	}
	defer lis.Close()
	RunUDPServer(lis, c, getCreateFuncOfUDPRemoteServer)
}

func getCreateFuncOfUDPLocalServer(c *ss.Config) func(*utils.SubConn) (net.Conn, net.Conn, error) {
	return func(conn *utils.SubConn) (c1, c2 net.Conn, err error) {
		var subconfig *ss.Config
		if len(c.Backends) != 0 && c.Type == "socksproxy" {
			subconfig = c.Backends[rand.Int()%len(c.Backends)]
		} else {
			subconfig = c
		}
		rconn, err := ss.DialUDP(subconfig)
		if err != nil {
			c.InitRuntime().Logger.Println(err)
			return
		}
		c1 = conn
		c2 = &udpLocalConn{Conn: newFECConn(rconn, subconfig)}
		return
	}
}

func RunUDPLocalServer(c *ss.Config) {
	listener, err := utils.NewUDPListener(c.Localaddr)
	if err != nil {
		c.InitRuntime().Logger.Fatal(err)
	}
	defer listener.Close()
	RunUDPServer(listener, c, getCreateFuncOfUDPLocalServer)
}

func newFECConn(conn net.Conn, cfg *ss.Config) net.Conn {
	if cfg != nil && cfg.DataShard > 0 && cfg.ParityShard > 0 {
		return utils.NewFecConn(conn, cfg.DataShard, cfg.ParityShard)
	}
	return conn
}
