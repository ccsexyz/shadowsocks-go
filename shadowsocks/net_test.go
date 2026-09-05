package ss

import (
	"crypto/rand"
	"net"
	"sync"
	"testing"
)

func TestHasCryptoConn(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()

	bc := NewBaseConnForTest(client)

	// Plain BaseConn → no CryptoConn
	if HasCryptoConn(bc) {
		t.Error("plain BaseConn should not have CryptoConn")
	}

	// CryptoConn wrapping BaseConn → should detect
	cc := NewCryptoConnStreamForTest(bc)
	if !HasCryptoConn(cc) {
		t.Error("CryptoConn should be detected directly")
	}

	// RemainConn wrapping CryptoConn → should detect through unwrap
	rc := NewRemainConnForTest(cc, []byte("residual"))
	if !HasCryptoConn(rc) {
		t.Error("CryptoConn should be detected through RemainConn")
	}

	// RemainConn without CryptoConn → should not detect
	plainRC := NewRemainConnForTest(bc, []byte("data"))
	if HasCryptoConn(plainRC) {
		t.Error("RemainConn without CryptoConn should not be detected")
	}
}

func TestHttpProxyDetector_RejectsNonHTTPData(t *testing.T) {
	lis := &listener{c: &Config{}}
	lis.c.initRuntime()

	randomData := make([]byte, 64)
	if _, err := rand.Read(randomData); err != nil {
		t.Fatal(err)
	}

	// Ensure first byte is not a SOCKS version
	for randomData[0] == verSocks4 || randomData[0] == verSocks5 || randomData[0] == verSocks6 {
		if _, err := rand.Read(randomData[:1]); err != nil {
			t.Fatal(err)
		}
	}

	mc := newMockConn()
	mc.readBuf = randomData
	conn := newBaseConn(mc, nil)

	for range 10 {
		_, matched := httpProxyDetector(conn, randomData, len(randomData), lis)
		if matched {
			t.Fatalf("httpProxyDetector should not match random encrypted data (byte0=0x%02x)", randomData[0])
		}
	}
}

func TestHttpProxyDetector_AcceptsValidHTTP(t *testing.T) {
	lis := &listener{c: &Config{}}
	lis.c.initRuntime()

	httpData := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	mc := newMockConn()
	mc.readBuf = httpData
	conn := newBaseConn(mc, nil)

	_, matched := httpProxyDetector(conn, httpData, len(httpData), lis)
	if !matched {
		t.Error("httpProxyDetector should match valid HTTP GET request")
	}
}

func TestHttpProxyDetector_SOCKSVersionBytesNotMatched(t *testing.T) {
	lis := &listener{c: &Config{}}
	lis.c.initRuntime()

	tests := []byte{verSocks4, verSocks5, verSocks6}
	for _, ver := range tests {
		data := make([]byte, 64)
		data[0] = ver

		mc := newMockConn()
		mc.readBuf = data
		conn := newBaseConn(mc, nil)

		_, matched := httpProxyDetector(conn, data, len(data), lis)
		if matched {
			t.Errorf("httpProxyDetector should not match SOCKS version 0x%02x", ver)
		}
	}
}

// TestListenerCloseConcurrent pins Close idempotence: concurrent double
// closes used to panic on the die channel.
func TestListenerCloseConcurrent(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	lis := &listener{
		rawlis: raw,
		die:    make(chan bool),
		connch: make(chan Conn, 1),
		errch:  make(chan error, 1),
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lis.Close()
		}()
	}
	wg.Wait()
}

// TestSocks5Detector_FragmentedGreeting pins the fragmented-greeting fix:
// RFC 1928 clients may split the method greeting across TCP segments, and
// the detector must accumulate the remainder from the raw connection
// instead of rejecting. The conn shape mirrors the production peek: the
// acceptor consumed the first n bytes and wrapped them in a RemainConn.
func TestSocks5Detector_FragmentedGreeting(t *testing.T) {
	lis := &listener{c: &Config{}}
	lis.c.initRuntime()

	// Remainder of the stream after the peeked segment: the missing greeting
	// method byte, then a CONNECT request for 127.0.0.1:80.
	rest := []byte{0x00}
	rest = append(rest, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50)
	mc := newMockConn()
	mc.readBuf = rest
	raw := newBaseConn(mc, nil)

	peeked := &RemainConn{remain: []byte{0x05, 0x01}, Conn: raw}
	buf := make([]byte, buffersize)
	copy(buf, peeked.remain)

	result, matched := socks5Detector(peeked, buf, 2, lis)
	if !matched {
		t.Fatal("socks5Detector should match VER=5")
	}
	if result.Action != AcceptContinue {
		t.Fatalf("fragmented greeting rejected: action=%v", result.Action)
	}
	if result.Conn != raw {
		t.Fatalf("expected the unwrapped raw conn, got %T", result.Conn)
	}
	if got := mc.getWritten(); len(got) < 2 || got[0] != 0x05 || got[1] != 0x00 {
		t.Fatalf("method reply = %x, want 0500 prefix", got)
	}
}

// TestSocks5Detector_TruncatedGreeting rejects a client that claims more
// methods than it ever sends.
func TestSocks5Detector_TruncatedGreeting(t *testing.T) {
	lis := &listener{c: &Config{}}
	lis.c.initRuntime()

	mc := newMockConn() // empty stream: greeting never completes
	raw := newBaseConn(mc, nil)
	peeked := &RemainConn{remain: []byte{0x05, 0x01}, Conn: raw}
	buf := make([]byte, buffersize)
	copy(buf, peeked.remain)

	result, matched := socks5Detector(peeked, buf, 2, lis)
	if !matched {
		t.Fatal("socks5Detector should match VER=5")
	}
	if result.Action != AcceptReject {
		t.Fatalf("truncated greeting accepted: action=%v", result.Action)
	}
}

// TestSocks5Detector_SingleSegmentGreeting guards the unfragmented path:
// a greeting that arrives whole must keep working unchanged.
func TestSocks5Detector_SingleSegmentGreeting(t *testing.T) {
	lis := &listener{c: &Config{}}
	lis.c.initRuntime()

	rest := []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50}
	mc := newMockConn()
	mc.readBuf = nil
	raw := newBaseConn(mc, nil)
	peeked := &RemainConn{remain: rest, Conn: raw}
	buf := make([]byte, buffersize)
	copy(buf, rest)

	result, matched := socks5Detector(peeked, buf, len(rest), lis)
	if !matched {
		t.Fatal("socks5Detector should match VER=5")
	}
	if result.Action != AcceptContinue {
		t.Fatalf("single-segment greeting rejected: action=%v", result.Action)
	}
}

// TestSocks5RejectsMethodsWithoutNoAuth pins RFC 1928 method negotiation: a
// client that does not offer no-auth gets 0xFF and a reject, instead of a
// silent {5,0} that strict clients then abort on.
func TestSocks5RejectsMethodsWithoutNoAuth(t *testing.T) {
	lis := &listener{c: &Config{}}
	lis.c.initRuntime()
	mc := newMockConn()
	raw := newBaseConn(mc, nil)
	peeked := []byte{5, 1, 2} // only user/pass offered
	buf := make([]byte, buffersize)
	copy(buf, peeked)
	conn := &RemainConn{remain: DupBuffer(peeked), Conn: raw}

	result, matched := socks5Detector(conn, buf, len(peeked), lis)
	if !matched {
		t.Fatal("socks5Detector should match VER=5")
	}
	if result.Action != AcceptReject {
		t.Fatalf("action = %v, want reject", result.Action)
	}
	if got := mc.getWritten(); len(got) != 2 || got[0] != 5 || got[1] != 0xFF {
		t.Fatalf("reply = %x, want 05ff", got)
	}
}

// TestSocks6ShortRequestNoPanic pins the n<3 guard: VER+CMD without an ATYP
// byte must reject, not reach ParseAddr with a truncated buffer.
func TestSocks6ShortRequestNoPanic(t *testing.T) {
	lis := &listener{c: &Config{}}
	lis.c.initRuntime()
	mc := newMockConn()
	raw := newBaseConn(mc, nil)
	peeked := []byte{verSocks6, cmdConnect}
	buf := make([]byte, buffersize)
	copy(buf, peeked)
	conn := &RemainConn{remain: DupBuffer(peeked), Conn: raw}

	result, matched := socks6Detector(conn, buf, len(peeked), lis)
	if !matched {
		t.Fatal("socks6Detector should match VER=6")
	}
	if result.Action != AcceptReject {
		t.Fatalf("action = %v, want reject", result.Action)
	}
}

// TestSocks4DropsPeekedRequest pins the framing-strip fix: the SOCKS4 request
// bytes must not be replayed into the tunneled stream.
func TestSocks4DropsPeekedRequest(t *testing.T) {
	lis := &listener{c: &Config{}}
	lis.c.initRuntime()
	mc := newMockConn()
	raw := newBaseConn(mc, nil)
	req := []byte{4, 1, 0x01, 0xBB, 127, 0, 0, 1, 0} // CONNECT 127.0.0.1:443
	buf := make([]byte, buffersize)
	copy(buf, req)
	conn := &RemainConn{remain: DupBuffer(req), Conn: raw}

	result, matched := socks4Detector(conn, buf, len(req), lis)
	if !matched {
		t.Fatal("socks4Detector should match")
	}
	if result.Action != AcceptContinue {
		t.Fatalf("action = %v, want continue", result.Action)
	}
	if result.Conn != raw {
		t.Fatalf("conn = %T, want the unwrapped raw conn", result.Conn)
	}
	if got := mc.getWritten(); len(got) != 8 || got[0] != 0 || got[1] != 0x5A {
		t.Fatalf("socks4 reply = %x, want 8-byte 005a grant", got)
	}
}
