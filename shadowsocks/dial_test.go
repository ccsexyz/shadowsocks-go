package ss

import (
	"testing"
)

func TestDialSocks5WithOptions_DataWrite(t *testing.T) {
	// Verify dialSocks5WithOptions writes opt.Data after handshake.
	// We can't easily test the full SOCKS5 flow without a real proxy,
	// but we can verify the function signature and basic path.
	opt := &DialOptions{
		Target: "127.0.0.1:80",
		C: &Config{
			CryptoConfig: CryptoConfig{Method: "socks5"},
			NetworkConfig: NetworkConfig{
				Remoteaddr: "127.0.0.1:1", // will fail, but we test error path
			},
		},
		Data: []byte("test-data"),
	}
	_, err := dialSocks5WithOptions(opt)
	if err == nil {
		t.Error("expected error dialing to 127.0.0.1:1")
	}
	// Data should NOT be nil'd on error path
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

func TestDialSSWithOptions_Socks5(t *testing.T) {
	// Verify socks5 path is taken when Method is "socks5"
	c := &Config{
		CryptoConfig: CryptoConfig{Method: "socks5"},
		NetworkConfig: NetworkConfig{
			Remoteaddr: "127.0.0.1:1",
			Timeout:    1,
		},
	}
	CheckBasicConfig(c)

	opt := &DialOptions{
		Target: "127.0.0.1:80",
		C:      c,
	}
	_, err := dialSSWithOptions(opt)
	if err == nil {
		t.Error("expected connection error dialing to 127.0.0.1:1")
	}
}

func TestDialSSWithOptions_BackendsEmpty(t *testing.T) {
	// Verify error when no backends are available
	c := &Config{
		CryptoConfig: CryptoConfig{Method: "aes-128-gcm", Password: "test"},
		NetworkConfig: NetworkConfig{
			Remoteaddr: "127.0.0.1:1",
			Timeout:    1,
		},
	}
	CheckBasicConfig(c)

	opt := &DialOptions{
		Target: "127.0.0.1:80",
		C:      c,
	}
	_, err := dialSSWithOptions(opt)
	if err == nil {
		t.Error("expected connection error")
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
	// opt.Data should be nil'd after backends loop (line 186)
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
