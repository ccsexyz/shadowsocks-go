package ss

import (
	"crypto/rand"
	"net"
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
	cc := NewCryptoConnForTest(bc)
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
