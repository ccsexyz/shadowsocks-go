package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strconv"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

type udpLocalConn struct {
	ss.Conn
}

func (conn *udpLocalConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	var b []byte
	if buf != nil && len(buf) >= 3 {
		b = buf
	} else {
		b = make([]byte, 65536)
	}
	// Read SIP022-format response from SS tunnel
	segs, err := conn.Conn.Read(b[3:], pool)
	if err != nil {
		return nil, err
	}
	n := 0
	for _, s := range segs {
		n += len(s)
	}
	// Flatten into b if segments are not in b[3:]
	if len(segs) > 0 && cap(segs[0]) > 0 && &segs[0][0] != &b[3] {
		off := 3
		for _, s := range segs {
			off += copy(b[off:], s)
		}
	}
	// Parse SIP022 and convert to SOCKS5: [RSV(2)][FRAG(1)][ATYP(1)][ADDR][PORT(2)][PAYLOAD]
	hdr, host, port, payload, perr := crypto.ParseSIP022(b[3 : 3+n])
	if perr != nil {
		// Not SIP022 — pass through as-is (compat with old format)
		_ = hdr
		b[0] = 0
		b[1] = 0
		b[2] = 0
		return [][]byte{b[:n+3]}, nil
	}
	return [][]byte{b[:crypto.BuildSOCKS5Response(b, host, port, payload)]}, nil
}

func (conn *udpLocalConn) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		if len(b) < 3 {
			return n, fmt.Errorf("the length of buffer can't be less than three")
		}
		sipPkt := crypto.BuildSIP022Request(b[3:])
		_, err = conn.Conn.Write(sipPkt)
		if err != nil {
			return n, err
		}
		n += len(b)
	}
	return
}

type udpRemoteConn struct {
	net.Conn
	header []byte // SIP022 header: [Type][TS][PadLen][Pad][Addr][Port]
}

func (conn *udpRemoteConn) readFromTarget(b []byte) (n int, err error) {
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

// writePayload extracts SIP022/ATYP payload and writes to the target.
func (conn *udpRemoteConn) writePayload(b []byte) (int, error) {
	payload := crypto.Sip022Payload(b)
	if payload == nil {
		var err error
		_, payload, err = ss.ParseAddr(b)
		if err != nil {
			log.Printf("[UDP] remote Write: parse failed: %v", err)
			return 0, err
		}
	}
	_, err := conn.Conn.Write(payload)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (conn *udpRemoteConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	var b []byte
	if buf != nil {
		b = buf
	} else if pool != nil {
		b = pool.Get(65536)
	} else {
		b = make([]byte, 65536)
	}
	n, err := conn.readFromTarget(b)
	if err != nil {
		return nil, err
	}
	return [][]byte{b[:n]}, nil
}

func (conn *udpRemoteConn) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		nn, e := conn.writePayload(b)
		n += nn
		if e != nil {
			return n, e
		}
	}
	return
}

func getCreateFuncOfUDPRemoteServer(c *ss.Config) func(*utils.SubConn) (utils.Conn, utils.Conn, error) {
	return func(subconn *utils.SubConn) (c1, c2 utils.Conn, err error) {
		buf := utils.GetBuf(65536)
		defer utils.PutBuf(buf)
		n, err := subconn.Read(buf)
		if err != nil {
			log.Printf("udp remote handler: SubConn.Read failed: %v", err)
			return
		}
		b := buf[:n]

		// Try SIP022 format first, fall back to legacy ATYP format
		var sipHdr []byte
		_, host, port, data, perr := crypto.ParseSIP022(b)
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
			port, _ = strconv.Atoi(addr.Port())
			sipHdr = b[:len(b)-len(data)] // legacy header: ATYP+ADDR+PORT
		}

		target := net.JoinHostPort(host, portStr(port))

		var rconn utils.Conn
		if len(c.Backends) != 0 && c.Type == "ssproxy" {
			v := c.Backends[rand.Int()%len(c.Backends)]
			rconn, err = ss.DialUDP(v)
			if err != nil {
				return
			}
			rconn.Write(b)
			c1 = ss.AsNetConn(subconn)
			c2 = rconn
			return
		}
		rc, err := net.Dial("udp", target)
		if err != nil {
			log.Printf("udp remote handler: dial target %s failed: %v", target, err)
			return
		}
		rconn = ss.AsNetConn(rc)
		_, err = rconn.Write(data)
		if err != nil {
			log.Printf("udp remote handler: write to target %s failed: %v", target, err)
			return
		}
		c1 = ss.AsNetConn(subconn)
		c2 = &udpRemoteConn{
			Conn:   rc,
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

func getCreateFuncOfUDPLocalServer(c *ss.Config) func(*utils.SubConn) (utils.Conn, utils.Conn, error) {
	return func(conn *utils.SubConn) (c1, c2 utils.Conn, err error) {
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
		c1 = ss.AsNetConn(conn)
		c2 = &udpLocalConn{Conn: rconn}
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
