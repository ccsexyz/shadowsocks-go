package ss

import (
	"io"
	"net"
	"strings"
	"testing"
)

// TestDialSocks5WithOptions_DataWrite pins that opt.Data survives a dial
// error: the socks5 error path must not nil it out.
func TestDialSocks5WithOptions_DataWrite(t *testing.T) {
	opt := &DialOptions{
		Target: "127.0.0.1:80",
		C: &Config{
			CryptoConfig: CryptoConfig{Method: "socks5"},
			NetworkConfig: NetworkConfig{
				Remoteaddr: "127.0.0.1:1", // unreachable: exercises the error path
			},
		},
		Data: []byte("test-data"),
	}
	_, err := dialSocks5WithOptions(opt)
	if err == nil {
		t.Error("expected error dialing to 127.0.0.1:1")
	}
	if opt.Data == nil {
		t.Error("opt.Data should not be nil on error path")
	}
}

func TestCheckAndModifyTarget_NoLocalResolve(t *testing.T) {
	opt := &DialOptions{
		Target: "example.com:80",
		C: &Config{
			ProxyConfig: ProxyConfig{},
		},
		Data: []byte("test"),
	}
	newOpt, err := checkAndModifyTarget(opt)
	if err != nil {
		t.Fatal(err)
	}
	if newOpt != nil {
		t.Error("expected nil newOpt when LocalResolve is false")
	}
}

func TestCheckAndModifyTarget_NoIPv4(t *testing.T) {
	opt := &DialOptions{
		Target: "1.2.3.4:80",
		C: &Config{
			ProxyConfig:   ProxyConfig{},
			NetworkConfig: NetworkConfig{LocalResolve: true, NoIPv4: true},
		},
	}
	_, err := checkAndModifyTarget(opt)
	if err == nil {
		t.Error("expected error for IPv4 when NoIPv4 is set")
	}
}

func TestCheckAndModifyTarget_NoIPv6(t *testing.T) {
	opt := &DialOptions{
		Target: "[::1]:80",
		C: &Config{
			ProxyConfig:   ProxyConfig{},
			NetworkConfig: NetworkConfig{LocalResolve: true, NoIPv6: true},
		},
	}
	_, err := checkAndModifyTarget(opt)
	if err == nil {
		t.Error("expected error for IPv6 when NoIPv6 is set")
	}
}

func TestDialSSWithOptions_BackendsWithSocks5(t *testing.T) {
	// Verify backends loop works when one backend has method "socks5"
	c := &Config{
		CryptoConfig: CryptoConfig{Method: "aes-128-gcm", Password: "test"},
		NetworkConfig: NetworkConfig{
			Remoteaddr: "127.0.0.1:1",
		},
		Backends: []*Config{{
			CryptoConfig:  CryptoConfig{Method: "socks5"},
			NetworkConfig: NetworkConfig{Remoteaddr: "127.0.0.1:1", Timeout: 1},
		}},
	}
	CheckConfig(c)

	opt := &DialOptions{
		Target: "127.0.0.1:80",
		C:      c,
		Data:   []byte("hello"),
	}
	_, err := dialSSWithOptions(opt)
	if err == nil {
		t.Error("expected connection error to unreachable backend")
	}
	// opt.Data should be nil'd after the backends loop
	if opt.Data != nil {
		t.Error("opt.Data should be nil after backends loop returns")
	}
}

func TestDialSSWithOptions_CheckAndModifyTarget_PreventsDoubleWrite(t *testing.T) {
	// When checkAndModifyTarget creates a new opt (LocalResolve=true, domain resolves),
	// the original opt.Data should be nil'd to prevent double-write.
	c := &Config{
		CryptoConfig: CryptoConfig{Method: "aes-128-gcm", Password: "test"},
		NetworkConfig: NetworkConfig{
			LocalResolve: true,
			Remoteaddr:   "127.0.0.1:1",
			Timeout:      1,
		},
	}
	CheckBasicConfig(c)

	opt := &DialOptions{
		Target: "localhost:80", // domain that resolves to 127.0.0.1
		C:      c,
		Data:   []byte("test-data"),
	}
	_, _ = dialSSWithOptions(opt)
	// After checkAndModifyTarget creates newOpt, opt.Data should be nil
	if opt.Data != nil {
		t.Error("opt.Data should be nil after checkAndModifyTarget creates newOpt")
	}
}

// TestDialSSWithOptions_BackendsWinnerUsable pins the multi-backend race
// contract: the conn returned by dialSSWithOptions must be the one handed off
// by its dialer goroutine and must be immediately usable. The pre-fix shape
// (buffered conch + post-send die re-check) could close the winner when the
// sender was preempted between its buffered send and the re-check.
func TestDialSSWithOptions_BackendsWinnerUsable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				io.Copy(io.Discard, nc)
				nc.Close()
			}()
		}
	}()

	backends := make([]*Config, 4)
	for i := range backends {
		backends[i] = &Config{
			CryptoConfig:  CryptoConfig{Method: "plain"},
			NetworkConfig: NetworkConfig{Remoteaddr: ln.Addr().String(), Timeout: 5},
		}
	}
	c := &Config{Backends: backends}
	CheckConfig(c)

	for round := 0; round < 50; round++ {
		opt := &DialOptions{Target: "127.0.0.1:80", C: c}
		conn, err := dialSSWithOptions(opt)
		if err != nil {
			t.Fatalf("round %d: dial: %v", round, err)
		}
		if conn == nil {
			t.Fatalf("round %d: nil conn", round)
		}
		// A closed-winner race surfaces here as "use of a closed network
		// connection"; the fix must make every round succeed.
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatalf("round %d: winner conn unusable: %v", round, err)
		}
		conn.Close()
	}
}

// TestDialSSWithOptions_BackendsAllFailLastError pins error transparency:
// when every backend fails, the returned error wraps the last dial failure
// instead of the bare errNoBackends sentinel.
func TestDialSSWithOptions_BackendsAllFailLastError(t *testing.T) {
	backends := make([]*Config, 2)
	for i := range backends {
		backends[i] = &Config{
			CryptoConfig:  CryptoConfig{Method: "plain"},
			NetworkConfig: NetworkConfig{Remoteaddr: "127.0.0.1:1", Timeout: 1},
		}
	}
	c := &Config{Backends: backends}
	CheckConfig(c)

	opt := &DialOptions{Target: "127.0.0.1:80", C: c}
	_, err := dialSSWithOptions(opt)
	if err == nil {
		t.Fatal("expected error when all backends fail")
	}
	if !strings.Contains(err.Error(), "no available backends") {
		t.Fatalf("err = %v, want it to mention no available backends", err)
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Fatalf("err = %v, want it to wrap the underlying dial failure", err)
	}
}
