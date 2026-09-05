package server

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// End-to-end tests for the UDP relay format invariant: a 2022 tunnel carries
// SIP022 payloads exclusively — every sender wraps legacy-shaped payloads
// with BuildSIP022Request, and the 2022 receiver validates strictly. These
// pin the fix for silent drops of bare IPv4 packets whose payload bytes
// aliased as a stale SIP022 header (e.g. DNS queries for domains whose
// first QNAME label is 1 or 4 bytes long).

const test2022psk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
const test2022method = "2022-blake3-aes-256-gcm"
const testClassicMethod = "aes-256-gcm"
const testClassicPw = "udp-format-classic-pw"

// freeUDPPort binds an ephemeral port, reports it, and releases it for the
// server under test to rebind. (The SS UDP servers don't surface their
// listener, so the port must be chosen up front.)
func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	conn.Close()
	return port
}

// waitUDPBound polls addr with a probe datagram until the port stops
// answering ICMP port-unreachable, i.e. some socket is bound there. Probe
// packets are garbage that the SS servers drop (or the udptun relays —
// harmless noise).
func waitUDPBound(t *testing.T, addr string) {
	t.Helper()
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	deadline := time.Now().Add(3 * time.Second)
	for {
		probe.Write([]byte{0})
		probe.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
		buf := make([]byte, 16)
		if _, err := probe.Read(buf); err == nil {
			return // something answered (e.g. udptun echo) — definitely bound
		} else if !isConnRefused(err) {
			return // timeout: ICMP not reported → bound (or lost); good enough
		}
		if time.Now().After(deadline) {
			t.Fatalf("udp server at %s never came up", addr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func isConnRefused(err error) bool {
	oe, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	return oe.Err.Error() == "connection refused" || oe.Err.Error() == "connect: connection refused"
}

// startUDPRemoteBackend runs an SS UDP server and returns a dialer config
// (Remoteaddr = the server's listen address) for use as a Backend/Backends
// entry by udptun / relay / socksproxy configs.
func startUDPRemoteBackend(t *testing.T, method, password string) *ss.Config {
	t.Helper()
	srv := &ss.Config{}
	srv.Type = "server"
	srv.Localaddr = "127.0.0.1:" + strconv.Itoa(freeUDPPort(t))
	srv.Method = method
	srv.Password = password
	srv.UDPRelay = true
	ss.CheckConfig(srv)
	t.Cleanup(func() { srv.Close() })
	go RunUDPRemoteServer(srv)
	waitUDPBound(t, srv.Localaddr)

	dial := &ss.Config{}
	dial.Remoteaddr = srv.Localaddr
	dial.Method = method
	dial.Password = password
	ss.CheckConfig(dial)
	return dial
}

// dnsQueryPayload builds a plain DNS query for qname (the app-level UDP
// payload a stub resolver would send).
func dnsQueryPayload(qname string) []byte {
	dns := make([]byte, 12)
	dns[0], dns[1] = 0xab, 0xcd
	dns[2] = 0x01
	dns[5] = 1
	for _, label := range dnsLabels(qname) {
		dns = append(dns, byte(len(label)))
		dns = append(dns, label...)
	}
	dns = append(dns, 0, 0, 1, 0, 1)
	return dns
}

func dnsLabels(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == '.' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// TestUDPTunSIP022BackendDNSQueryRoundTrip drives the aliasing case end to
// end: DNS queries must round-trip through a 2022 udptun backend, whose
// requests are SIP022-wrapped and validated strictly on arrival.
func TestUDPTunSIP022BackendDNSQueryRoundTrip(t *testing.T) {
	echoAddr, _ := udpEchoServer(t)

	backend := startUDPRemoteBackend(t, test2022method, test2022psk)

	udptun := &ss.Config{}
	udptun.Type = "udptun"
	udptun.Localaddr = "127.0.0.1:" + strconv.Itoa(freeUDPPort(t))
	udptun.Backend = backend
	udptun.Remoteaddr = echoAddr
	ss.CheckConfig(udptun)
	t.Cleanup(func() { udptun.Close() })
	go RunUDPTunServer(udptun)
	waitUDPBound(t, udptun.Localaddr)

	udpAddr, err := net.ResolveUDPAddr("udp", udptun.Localaddr)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for _, qname := range []string{"m.google.com", "a.pp.ua", "mail.google.com", "www.google.com"} {
		query := dnsQueryPayload(qname)
		if _, err := client.Write(query); err != nil {
			t.Fatalf("%s: write: %v", qname, err)
		}
		client.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("%s: no echo through 2022 backend (packet dropped?): %v", qname, err)
		}
		if !bytes.Equal(buf[:n], query) {
			t.Fatalf("%s: echo mismatch: got %d bytes, want %d", qname, n, len(query))
		}
		t.Logf("%s: round-trip OK via 2022 backend", qname)
	}
}

// TestUDPTunClassicBackendRoundTrip verifies the classic-backend udptun path
// still works: bare ATYP requests in, bare ATYP responses out.
func TestUDPTunClassicBackendRoundTrip(t *testing.T) {
	echoAddr, _ := udpEchoServer(t)

	backend := startUDPRemoteBackend(t, testClassicMethod, testClassicPw)

	udptun := &ss.Config{}
	udptun.Type = "udptun"
	udptun.Localaddr = "127.0.0.1:" + strconv.Itoa(freeUDPPort(t))
	udptun.Backend = backend
	udptun.Remoteaddr = echoAddr
	ss.CheckConfig(udptun)
	t.Cleanup(func() { udptun.Close() })
	go RunUDPTunServer(udptun)
	waitUDPBound(t, udptun.Localaddr)

	udpAddr, err := net.ResolveUDPAddr("udp", udptun.Localaddr)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for i := 0; i < 3; i++ {
		payload := dnsQueryPayload("m.google.com")
		if _, err := client.Write(payload); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		client.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("echo %d mismatch", i)
		}
	}
}

// TestSSProxyUDPRelayCrossMethodRoundTrip drives the multi-backend UDP relay
// with one 2022 and one classic backend: whichever backend a datagram lands
// on, the relay must rewrite it into that backend's format (and the response
// back into the client's), so both cipher families round-trip.
func TestSSProxyUDPRelayCrossMethodRoundTrip(t *testing.T) {
	echoAddr, _ := udpEchoServer(t)

	backend2022 := startUDPRemoteBackend(t, test2022method, test2022psk)
	backendClassic := startUDPRemoteBackend(t, testClassicMethod, testClassicPw)

	relay := &ss.Config{}
	relay.Type = "ssproxy"
	relay.Localaddr = "127.0.0.1:" + strconv.Itoa(freeUDPPort(t))
	relay.UDPRelay = true
	relay.Backends = []*ss.Config{backend2022, backendClassic}
	ss.CheckConfig(relay)
	t.Cleanup(func() { relay.Close() })
	go RunMultiUDPRemoteServer(relay)
	waitUDPBound(t, relay.Localaddr)

	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)
	target := []byte{1, 127, 0, 0, 1, byte(echoPort >> 8), byte(echoPort)}

	// Legacy-method client: bare payloads. Exercises legacy→2022 (wrap) and
	// legacy→classic (pass-through) forward paths plus the matching response
	// translations.
	t.Run("legacy_client", func(t *testing.T) {
		cli := &ss.Config{}
		cli.Method = testClassicMethod
		cli.Password = testClassicPw
		cli.Remoteaddr = relay.Localaddr
		ss.CheckConfig(cli)

		conn, err := ss.DialUDP(cli)
		if err != nil {
			t.Fatal("DialUDP:", err)
		}
		defer conn.Close()

		for i := 0; i < 24; i++ {
			payload := dnsQueryPayload("m.google.com")
			if _, err := conn.Write(append(append([]byte{}, target...), payload...)); err != nil {
				t.Fatalf("send %d: %v", i, err)
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp := make([]byte, 4096)
			n, err := ss.ReadN(conn, resp, nil)
			if err != nil {
				t.Fatalf("recv %d: %v", i, err)
			}
			// Relay → legacy client: bare ATYP(1)+IPv4+port header.
			if !bytes.Equal(resp[7:n], payload) {
				t.Fatalf("recv %d: payload mismatch (%d bytes echoed)", i, n-7)
			}
		}
	})

	// 2022 client: SIP022 payloads. Exercises 2022→2022 (pass-through) and
	// 2022→classic (unwrap) forward paths.
	t.Run("sip022_client", func(t *testing.T) {
		cli := &ss.Config{}
		cli.Method = test2022method
		cli.Password = test2022psk
		cli.Remoteaddr = relay.Localaddr
		ss.CheckConfig(cli)

		conn, err := ss.DialUDP(cli)
		if err != nil {
			t.Fatal("DialUDP:", err)
		}
		defer conn.Close()

		for i := 0; i < 24; i++ {
			payload := dnsQueryPayload("a.pp.ua")
			if _, err := conn.Write(crypto.BuildSIP022Request(append(append([]byte{}, target...), payload...))); err != nil {
				t.Fatalf("send %d: %v", i, err)
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			resp := make([]byte, 4096)
			n, err := ss.ReadN(conn, resp, nil)
			if err != nil {
				t.Fatalf("recv %d: %v", i, err)
			}
			// Relay → 2022 client: SIP022-wrapped response.
			_, _, _, got, err := crypto.ParseSIP022(resp[:n])
			if err != nil {
				t.Fatalf("recv %d: response not SIP022: %v", i, err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("recv %d: payload mismatch", i)
			}
		}
	})
}

// TestSocksProxyUDPClassicBackendRoundTrip pins the udpLocalConn fix: with a
// classic backend the SOCKS5-UDP payloads must go out bare (the old code
// wrapped unconditionally, which classic backends reject).
func TestSocksProxyUDPClassicBackendRoundTrip(t *testing.T) {
	echoAddr, _ := udpEchoServer(t)

	backend := startUDPRemoteBackend(t, testClassicMethod, testClassicPw)

	proxy := &ss.Config{}
	proxy.Type = "socksproxy"
	proxy.Localaddr = "127.0.0.1:" + strconv.Itoa(freeUDPPort(t))
	proxy.UDPRelay = true
	proxy.Backends = []*ss.Config{backend}
	ss.CheckConfig(proxy)
	t.Cleanup(func() { proxy.Close() })
	go RunUDPLocalServer(proxy)
	waitUDPBound(t, proxy.Localaddr)

	proxyAddr, err := net.ResolveUDPAddr("udp", proxy.Localaddr)
	if err != nil {
		t.Fatal(err)
	}
	client, err := net.DialUDP("udp", nil, proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	for i := 0; i < 3; i++ {
		payload := dnsQueryPayload("m.google.com")
		_, echoPortStr, _ := net.SplitHostPort(echoAddr)
		echoPort, _ := strconv.Atoi(echoPortStr)
		// SOCKS5 UDP request: RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2) payload
		pkt := []byte{0, 0, 0, 1, 127, 0, 0, 1, byte(echoPort >> 8), byte(echoPort)}
		pkt = append(pkt, payload...)
		if _, err := client.Write(pkt); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		client.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		// Response: RSV(2) FRAG(1) ATYP ADDR PORT payload — payload must match.
		if n < len(pkt) || !bytes.Equal(buf[n-len(payload):n], payload) {
			t.Fatalf("read %d: unexpected response (%d bytes)", i, n)
		}
	}
}

// TestMakeATYPHeader pins the address-family encoding: IPv4 → ATYP 1,
// IPv6 → ATYP 4 (not a domain literal), anything else → ATYP 3 domain.
// Every shape must round-trip through ParseAddr.
func TestMakeATYPHeader(t *testing.T) {
	cases := []struct {
		host     string
		wantATYP byte
	}{
		{"127.0.0.1", 1},
		{"2001:db8::1", 4},
		{"example.com", 3},
	}
	for _, tc := range cases {
		hdr := makeATYPHeader(tc.host, 443)
		if hdr[0] != tc.wantATYP {
			t.Errorf("makeATYPHeader(%q) ATYP = %d, want %d", tc.host, hdr[0], tc.wantATYP)
		}
		addr, _, err := ss.ParseAddr(hdr)
		if err != nil {
			t.Errorf("ParseAddr(%q header): %v", tc.host, err)
			continue
		}
		if addr.Host() != tc.host {
			t.Errorf("round-trip host = %q, want %q", addr.Host(), tc.host)
		}
		if addr.Port() != "443" {
			t.Errorf("round-trip port = %q, want 443", addr.Port())
		}
	}
}

// stubUDPConn implements ss.Conn for udpLocalConn unit tests.
type stubUDPConn struct {
	segs [][]byte // returned verbatim by Read
	// seq, when non-empty, is returned one entry per Read call; reads past
	// the end return io.EOF. Stands in for per-datagram tunnel reads.
	seq [][]byte
	idx int
}

func (c *stubUDPConn) Read(_ []byte, _ *utils.BufPool) ([][]byte, error) {
	if c.seq != nil {
		if c.idx >= len(c.seq) {
			return nil, io.EOF
		}
		s := c.seq[c.idx]
		c.idx++
		return [][]byte{s}, nil
	}
	return c.segs, nil
}

func (c *stubUDPConn) Write(_ ...[]byte) (int, error) {
	return 0, nil
}
func (c *stubUDPConn) Close() error                       { return nil }
func (c *stubUDPConn) LocalAddr() net.Addr                { return nil }
func (c *stubUDPConn) RemoteAddr() net.Addr               { return nil }
func (c *stubUDPConn) SetDeadline(t time.Time) error      { return nil }
func (c *stubUDPConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *stubUDPConn) SetWriteDeadline(t time.Time) error { return nil }

// stubNetConn implements net.Conn for udpRemoteConn unit tests: Read fills
// the buffer with min(len(buf), fill) pattern bytes, standing in for the
// target UDP socket.
type stubNetConn struct {
	fill int
}

func (c *stubNetConn) Read(buf []byte) (int, error) {
	n := len(buf)
	if n > c.fill {
		n = c.fill
	}
	for i := range buf[:n] {
		buf[i] = byte(i % 251)
	}
	return n, nil
}

func (c *stubNetConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *stubNetConn) Close() error                { return nil }
func (c *stubNetConn) LocalAddr() net.Addr         { return nil }
func (c *stubNetConn) RemoteAddr() net.Addr        { return nil }
func (c *stubNetConn) SetDeadline(_ time.Time) error {
	return nil
}
func (c *stubNetConn) SetReadDeadline(_ time.Time) error {
	return nil
}
func (c *stubNetConn) SetWriteDeadline(_ time.Time) error {
	return nil
}

// TestUDPRemoteConnResponseHeadroom pins the recvinto headroom fix: the
// target datagram is read into b[hdrlen:], so a max-size (65507B) target
// payload must survive in full behind a max-length SIP022 response header
// (89 bytes with the largest padding). A 65536-byte buffer truncates it.
func TestUDPRemoteConnResponseHeadroom(t *testing.T) {
	const payloadLen = 65507
	hdr := make([]byte, 0, 89)
	hdr = append(hdr, 1) // type: server response
	ts := uint64(time.Now().Unix())
	for shift := 56; shift >= 0; shift -= 8 {
		hdr = append(hdr, byte(ts>>uint(shift)))
	}
	hdr = append(hdr, 0, 0, 0, 0, 0, 0, 0, 0) // client session ID
	hdr = append(hdr, 0, 63)                  // padding length: max
	for i := 0; i < 63; i++ {
		hdr = append(hdr, 0)
	}
	hdr = append(hdr, 1, 127, 0, 0, 1, 0, 53) // ATYP header

	c := &udpRemoteConn{
		Conn:           &stubNetConn{fill: payloadLen},
		header:         hdr,
		sip22:          true,
		headerIsSIP022: true,
	}
	segs, err := c.Read(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) != 1 {
		t.Fatalf("seg count = %d", len(segs))
	}
	seg := segs[0]
	if len(seg) != len(hdr)+payloadLen {
		t.Fatalf("response truncated: got %d bytes, want %d", len(seg), len(hdr)+payloadLen)
	}
	// The stored header is copied in front with a refreshed timestamp...
	now := time.Now().Unix()
	var gotTS int64
	for i := 1; i < 9; i++ {
		gotTS = gotTS<<8 | int64(seg[i])
	}
	if d := gotTS - now; d < -5 || d > 5 {
		t.Fatalf("timestamp not refreshed: %d", gotTS)
	}
	// ...and the payload tail must be the complete pattern, not a prefix.
	want := byte((payloadLen - 1) % 251)
	if got := seg[len(seg)-1]; got != want {
		t.Fatalf("payload tail byte = %#x, want %#x (payload truncated?)", got, want)
	}
	if got := seg[len(hdr)]; got != 0x00 {
		t.Fatalf("payload head byte = %#x", got)
	}
}

// TestUDPLocalConnFlattenEmptyFirstSegment pins the flatten fix: when the
// tunnel conn returns an empty leading segment followed by data held
// outside the relay buffer, the data must still be flattened into the
// buffer before parsing (it used to be skipped, then parsed stale bytes).
// It also pins the response-format rule: a 2022 tunnel carries SIP022
// responses (rewritten to SOCKS5 UDP), a classic tunnel carries bare ATYP
// responses (prefixed with RSV/FRAG only).
func TestUDPLocalConnFlattenEmptyFirstSegment(t *testing.T) {
	payload := []byte("flatten-check-payload")
	bare := append([]byte{1, 127, 0, 0, 1, 0, 53}, payload...)
	sip := crypto.BuildSIP022Request(bare)

	t.Run("2022-tunnel-parses-sip022", func(t *testing.T) {
		c := &udpLocalConn{Conn: &stubUDPConn{segs: [][]byte{{}, sip}}, wrapSIP022: true}
		segs, err := c.Read(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(segs) != 1 {
			t.Fatalf("seg count = %d", len(segs))
		}
		seg := segs[0]
		// SOCKS5 UDP response: RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2) PAYLOAD.
		if len(seg) != 10+len(payload) {
			t.Fatalf("response len = %d, want %d", len(seg), 10+len(payload))
		}
		if seg[0] != 0 || seg[1] != 0 || seg[2] != 0 {
			t.Fatalf("missing RSV/FRAG prefix: %v", seg[:3])
		}
		if seg[3] != 1 || !bytes.Equal(seg[4:8], []byte{127, 0, 0, 1}) {
			t.Fatalf("rewritten addr mismatch: %v", seg[3:10])
		}
		if !bytes.Equal(seg[10:], payload) {
			t.Fatalf("payload lost or corrupted: %q", seg[10:])
		}
	})

	t.Run("classic-tunnel-passes-bare", func(t *testing.T) {
		c := &udpLocalConn{Conn: &stubUDPConn{segs: [][]byte{{}, bare}}}
		segs, err := c.Read(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(segs) != 1 {
			t.Fatalf("seg count = %d", len(segs))
		}
		seg := segs[0]
		if len(seg) != 3+len(bare) {
			t.Fatalf("response len = %d, want %d", len(seg), 3+len(bare))
		}
		if seg[0] != 0 || seg[1] != 0 || seg[2] != 0 {
			t.Fatalf("missing RSV/FRAG prefix: %v", seg[:3])
		}
		if !bytes.Equal(seg[3:], bare) {
			t.Fatal("bare response payload corrupted")
		}
	})

	t.Run("2022-tunnel-drops-bare", func(t *testing.T) {
		// A bare datagram on a 2022 tunnel is malformed: it must be dropped
		// (read again), not passed through to the client. The next datagram
		// (SIP022) is then delivered normally.
		c := &udpLocalConn{Conn: &stubUDPConn{seq: [][]byte{bare, sip}}, wrapSIP022: true}
		segs, err := c.Read(nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(segs) != 1 {
			t.Fatalf("seg count = %d", len(segs))
		}
		seg := segs[0]
		if len(seg) != 10+len(payload) {
			t.Fatalf("response len = %d, want the later SIP022 datagram rewritten", len(seg))
		}
		if !bytes.Equal(seg[10:], payload) {
			t.Fatalf("payload lost or corrupted: %q", seg[10:])
		}
	})
}

// TestUDPLocalConnWriteDropsUnwrappableRequest pins the 2022 request-wrap
// contract on the local conn: a datagram without a wrappable address (empty
// payload, or an unsupported ATYP) is skipped without panicking on the
// missing ATYP byte, and its bytes still count toward the returned n so the
// relay loop's short-write check does not tear the session down.
func TestUDPLocalConnWriteDropsUnwrappableRequest(t *testing.T) {
	c := &udpLocalConn{Conn: &stubUDPConn{}, wrapSIP022: true}

	// RSV/FRAG only: no ATYP byte at all.
	n, err := c.Write([]byte{0, 0, 0})
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("n = %d, want 3 (dropped datagrams must still count as consumed)", n)
	}

	// Unsupported ATYP=9.
	n, err = c.Write([]byte{0, 0, 0, 9, 1, 2, 3, 4})
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Fatalf("n = %d, want 8", n)
	}

	// A dropped datagram followed by a valid one: both counted, no error.
	n, err = c.Write([]byte{0, 0, 0, 9, 1}, []byte{0, 0, 0, 1, 127, 0, 0, 1, 0, 80, 'x'})
	if err != nil {
		t.Fatal(err)
	}
	if n != 5+11 {
		t.Fatalf("n = %d, want %d", n, 5+11)
	}
}
