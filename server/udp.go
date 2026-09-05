package server

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"strconv"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

type udpLocalConn struct {
	ss.Conn
	// wrapSIP022 is set when the tunnel method is a 2022 cipher: outgoing
	// payloads must then be SIP022-wrapped (BuildSIP022Request). Classic
	// methods carry bare ATYP payloads — wrapping those unconditionally
	// (the old behavior) made every classic UDP backend drop the packet.
	wrapSIP022 bool
}

func (conn *udpLocalConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	var b []byte
	if buf != nil && len(buf) >= 3 {
		b = buf
	} else {
		// 65536 holds any tunnel datagram (max 65507 on the wire); the extra
		// 128 bytes leave room for the SIP022 header and the SOCKS5 response
		// header rewritten in front of a max-size payload.
		b = make([]byte, 65536+128)
	}
	for {
		// Read response from SS tunnel into b[3:], leaving room for the
		// SOCKS5 UDP [RSV(2)][FRAG(1)] prefix.
		segs, err := conn.Conn.Read(b[3:], pool)
		if err != nil {
			return nil, err
		}
		n := 0
		for _, s := range segs {
			n += len(s)
		}
		// Flatten into b if the segments are not already laid out at b[3:].
		// Locate the first non-empty segment: an empty leading segment (empty
		// decrypted payload, reachable from an authenticated tunnel peer) must
		// not decide in-placeness — &segs[0][0] would panic, and skipping the
		// flatten over it would parse stale buffer content below.
		inPlace := false
		for _, s := range segs {
			if len(s) > 0 {
				inPlace = &s[0] == &b[3]
				break
			}
		}
		if !inPlace {
			off := 3
			for _, s := range segs {
				off += copy(b[off:], s)
			}
		}
		// The payload format follows the tunnel's cipher family — the same
		// flag that decides the request direction. Parsing the other shape
		// here cannot succeed for a genuine packet and only invites
		// format-guessing misreads (a bare ATYP=1 response whose bytes alias
		// a fresh SIP022 header would be silently rewritten).
		if conn.wrapSIP022 {
			_, host, port, payload, perr := crypto.ParseSIP022(b[3 : 3+n])
			if perr != nil {
				// 2022 tunnels carry SIP022 exclusively and the crypto layer
				// already authenticated every datagram, so a non-SIP022
				// response here is malformed: drop it and read the next one
				// (each iteration blocks on a fresh datagram, so this cannot
				// spin).
				log.Printf("[UDP] local: dropping non-SIP022 response from 2022 tunnel len=%d err=%v", n, perr)
				continue
			}
			// Convert to SOCKS5 UDP: [RSV(2)][FRAG(1)][ATYP(1)][ADDR][PORT(2)][PAYLOAD]
			return [][]byte{b[:crypto.BuildSOCKS5Response(b, host, port, payload)]}, nil
		}
		// Classic tunnel: bare [ATYP][ADDR][PORT][PAYLOAD] — add the SOCKS5
		// UDP prefix and pass through.
		b[0] = 0
		b[1] = 0
		b[2] = 0
		return [][]byte{b[:n+3]}, nil
	}
}

func (conn *udpLocalConn) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		if len(b) < 3 {
			return n, fmt.Errorf("the length of buffer can't be less than three")
		}
		payload := b[3:]
		if conn.wrapSIP022 {
			payload = crypto.BuildSIP022Request(b[3:])
			if payload == nil {
				// Not a wrappable address (bad ATYP / too short): the 2022
				// receiver would drop it anyway; skip instead of sending a
				// packet that violates the tunnel's payload format. The bytes
				// still count as consumed — the relay loop tears the session
				// down on a short write.
				atyp := byte(0)
				if len(b) > 3 {
					atyp = b[3]
				}
				log.Printf("[UDP] local: dropping unwrappable request datagram payloadLen=%d atyp=0x%02x", len(b)-3, atyp)
				n += len(b)
				continue
			}
		}
		_, err = conn.Conn.Write(payload)
		if err != nil {
			return n, err
		}
		n += len(b)
	}
	return
}

type udpRemoteConn struct {
	net.Conn
	header []byte // SIP022 or legacy ATYP header: [Type?][TS?][PadLen?][Pad][Addr][Port]
	// sip22 records the wire format decided when the session's first packet
	// was parsed. Guessing per packet misparsed legacy ATYP=1 responses as
	// SIP022 headers and silently truncated their payload.
	sip22 bool
	// headerIsSIP022 marks conn.header as a SIP022 header (server-side
	// sessions with a 2022 client) whose timestamp must be refreshed on
	// every response. Client-side sessions (udptun) carry a BARE
	// header where b[1:9] is the destination address — refreshing there
	// overwrote the target with a timestamp.
	headerIsSIP022 bool
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
		// SIP022 responses carry a fresh timestamp: a header frozen at
		// session creation fails the ±30s check on the client once the
		// session outlives it, cutting long-lived UDP flows.
		if conn.headerIsSIP022 && hdrlen >= 9 {
			binary.BigEndian.PutUint64(b[1:9], uint64(time.Now().Unix()))
		}
	}
	return
}

// writePayload extracts SIP022/ATYP payload and writes to the target.
func (conn *udpRemoteConn) writePayload(b []byte) (int, error) {
	if len(b) == 0 {
		// Empty datagrams are legal from an authenticated client; dropping
		// them keeps the relay alive instead of tearing the session down on
		// a parse failure.
		return 0, nil
	}
	var payload []byte
	if conn.sip22 {
		payload = crypto.Sip022Payload(b)
		if payload == nil {
			return 0, fmt.Errorf("[UDP] remote Write: malformed SIP022 packet len=%d", len(b))
		}
	} else {
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
		// readFromTarget reads the target datagram into b[hdrlen:], so the
		// buffer must exceed the 65507-byte wire maximum by the header
		// length or max-size target payloads get silently truncated.
		b = pool.Get(65536 + 128)
	} else {
		b = make([]byte, 65536+128)
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
		// A 0-byte payload is reachable from an authenticated client (0-length
		// datagrams pass through every layer below); without this guard the
		// b[0] in the parse-failure log below panics on the empty slice and
		// takes the whole process down.
		if n == 0 {
			return nil, nil, fmt.Errorf("udp remote handler: empty payload from %s", subconn.RemoteAddr())
		}
		b := buf[:n]

		// Try SIP022 format first, fall back to legacy ATYP format
		var sipHdr []byte
		_, host, port, data, perr := crypto.ParseSIP022(b)
		sip22 := perr == nil
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
		if c.Type == "ssproxy" {
			backends := c.SnapshotBackends()
			if len(backends) != 0 {
				v := backends[rand.Int()%len(backends)]
				rconn, err = ss.DialUDP(v)
				if err != nil {
					return
				}
				// The relay may hand a packet to a backend whose cipher
				// family differs from the client's; rewrite the payload
				// into the format the backend's method requires.
				backendSip22 := crypto.IsAEAD2022(v.Method)
				first := relayClientToBackend(b, sip22, backendSip22, host, port, data)
				if first == nil {
					// The first datagram failed format translation; without
					// this guard it would be written as an empty datagram.
					rconn.Close()
					return nil, nil, fmt.Errorf("udp remote handler: first datagram undecodable len=%d", len(b))
				}
				// Surface a failed first write immediately instead of letting
				// the session linger until the 60s expiry on a dead backend.
				if _, werr := rconn.Write(first); werr != nil {
					rconn.Close()
					return nil, nil, werr
				}
				c1 = ss.AsNetConn(subconn)
				c2 = &udpFormatRelayConn{Conn: rconn, clientSip22: sip22, backendSip22: backendSip22}
				return
			}
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
			Conn:           rc,
			header:         ss.DupBuffer(sipHdr),
			sip22:          sip22,
			headerIsSIP022: sip22,
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
	if ip6 := ip.To16(); ip6 != nil {
		// Encode IPv6 as ATYP=4 instead of a domain literal: every consumer
		// (ParseAddr, parseSIP022Addr) understands it and it saves bytes.
		hdr := make([]byte, 1+16+2)
		hdr[0] = 4 // ATYP IPv6
		copy(hdr[1:17], ip6)
		binary.BigEndian.PutUint16(hdr[17:19], uint16(port))
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
		if c.Type == "socksproxy" {
			backends := c.SnapshotBackends()
			if len(backends) != 0 {
				subconfig = backends[rand.Int()%len(backends)]
			}
		}
		if subconfig == nil {
			subconfig = c
		}
		rconn, err := ss.DialUDP(subconfig)
		if err != nil {
			c.InitRuntime().Logger.Println(err)
			return
		}
		c1 = ss.AsNetConn(conn)
		c2 = &udpLocalConn{Conn: rconn, wrapSIP022: crypto.IsAEAD2022(subconfig.Method)}
		return
	}
}

// sip022RequestConn wraps every outgoing datagram in a SIP022 request header
// (BuildSIP022Request) so a tunnel with a 2022 backend always carries
// spec-compliant payloads. Incoming datagrams pass through untouched: 2022
// responses are already SIP022 and are stripped by the peer-side
// udpRemoteConn.writePayload. Read direction is inherited from the embedded
// Conn.
type sip022RequestConn struct {
	ss.Conn
}

func (c *sip022RequestConn) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		pkt := crypto.BuildSIP022Request(b)
		if pkt == nil {
			// Not a wrappable address: sending it bare would violate the
			// 2022 tunnel's payload-format invariant; drop the datagram.
			log.Printf("[UDP] sip022: dropping unwrappable datagram len=%d", len(b))
			n += len(b)
			continue
		}
		if _, err = c.Conn.Write(pkt); err != nil {
			return n, err
		}
		n += len(b)
	}
	return
}

// udpFormatRelayConn translates UDP datagram formats between a relay client
// and a backend whose cipher family differs (ssproxy multi-backend). The
// client's format (sip22 vs bare ATYP) is pinned from its first packet, the
// backend's from its configured method; same-format pairs pass through
// untouched. Datagrams that fail translation are dropped (per-packet
// condition), not treated as session errors.
type udpFormatRelayConn struct {
	utils.Conn
	clientSip22  bool
	backendSip22 bool
}

func (c *udpFormatRelayConn) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		out := c.toBackend(b)
		if out == nil {
			// Malformed client datagram: drop it, keep the relay alive.
			log.Printf("[UDP] relay: dropping undecodable client packet len=%d", len(b))
			n += len(b)
			continue
		}
		if _, err = c.Conn.Write(out); err != nil {
			return n, err
		}
		n += len(b)
	}
	return
}

// toBackend rewrites one client datagram into the backend's format. Returns
// nil when the datagram cannot be translated.
func (c *udpFormatRelayConn) toBackend(b []byte) []byte {
	if c.clientSip22 == c.backendSip22 {
		return b
	}
	if c.backendSip22 {
		// Legacy client → 2022 backend: wrap in a fresh SIP022 request.
		return crypto.BuildSIP022Request(b)
	}
	// 2022 client → classic backend: strip the SIP022 wrapper.
	_, host, port, payload, err := crypto.ParseSIP022(b)
	if err != nil {
		return nil
	}
	return append(makeATYPHeader(host, port), payload...)
}

func (c *udpFormatRelayConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	segs, err := c.Conn.Read(buf, pool)
	if err != nil || len(segs) == 0 {
		return segs, err
	}
	if c.clientSip22 == c.backendSip22 {
		return segs, nil
	}
	out := make([][]byte, 0, len(segs))
	for _, s := range segs {
		t, ok := c.toClient(s)
		if ok {
			out = append(out, t)
		}
	}
	return out, nil
}

// toClient rewrites one backend datagram into the client's format. Returns
// ok=false when the datagram cannot be translated (dropped).
func (c *udpFormatRelayConn) toClient(b []byte) (out []byte, ok bool) {
	if c.backendSip22 {
		// 2022 backend → legacy client: strip the SIP022 wrapper.
		_, host, port, payload, err := crypto.ParseSIP022(b)
		if err != nil {
			log.Printf("[UDP] relay: dropping malformed backend packet len=%d: %v", len(b), err)
			return nil, false
		}
		return append(makeATYPHeader(host, port), payload...), true
	}
	// Classic backend → 2022 client: wrap the bare response (fresh timestamp).
	out = crypto.BuildSIP022Response(b, 0)
	return out, out != nil
}

// relayClientToBackend rewrites the relay's first client datagram into the
// chosen backend's format; host/port/data come from the parse already done
// by the create func. Same-format pairs pass through unchanged.
func relayClientToBackend(b []byte, clientSip22, backendSip22 bool, host string, port int, data []byte) []byte {
	switch {
	case clientSip22 == backendSip22:
		return b
	case backendSip22:
		// Legacy client → 2022 backend: wrap in a fresh SIP022 request.
		return crypto.BuildSIP022Request(b)
	default:
		// 2022 client → classic backend: strip the SIP022 wrapper.
		return append(makeATYPHeader(host, port), data...)
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
