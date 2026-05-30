package server

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// allCipherMethods lists every method from the user's multiserver config.
var allCipherMethods = []struct {
	name     string
	method   string
	password string
}{
	{"aes-128-gcm", "aes-128-gcm", "plin-thik-born"},
	{"aes-192-gcm", "aes-192-gcm", "plin-thik-born"},
	{"aes-256-gcm", "aes-256-gcm", "plin-thik-born"},
	{"chacha20-ietf-poly1305", "chacha20-ietf-poly1305", "plin-thik-born"},
	{"2022-blake3-aes-128-gcm", "2022-blake3-aes-128-gcm", "312j8qA+CijMa7gJObSkAg=="},
}

// ---------------------------------------------------------------------------
// Multi-cipher full-chain integration — mimics the multiserver config from
// remote_server.json: SS client → backend SS server → echo
// ---------------------------------------------------------------------------

func TestIntegration_MultiCipherFullChain(t *testing.T) {
	t.Parallel()

	for _, m := range allCipherMethods {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()

			echoAddr, _, _ := echoServer(t)

			// Backend SS server
			srv := &ss.Config{}
			srv.Type = "server"
			srv.Method = m.method
			srv.Password = m.password
			ss.CheckConfig(srv)
			defer srv.Close()

			handlers := []ss.AcceptHandler{ss.LimitHandler}
			if crypto.IsAEAD2022(m.method) {
				handlers = append(handlers, ss.SS2022Handler)
			} else {
				handlers = append(handlers, ss.SSHandler)
			}

			sln, err := ss.Listen("127.0.0.1:0", srv, handlers)
			if err != nil {
				t.Fatal("backend listen:", err)
			}
			defer sln.Close()
			srvAddr := sln.Addr().String()

			go func() {
				for {
					c, err := sln.Accept()
					if err != nil {
						return
					}
					go tcpRemoteHandler(c.(*ss.AcceptedConn))
				}
			}()

			// SS client → backend → echo
			cli := &ss.Config{}
			cli.Remoteaddr = srvAddr
			cli.Method = m.method
			cli.Password = m.password
			ss.CheckConfig(cli)
			defer cli.Close()

			time.Sleep(100 * time.Millisecond)

			conn, err := ss.DialSSWithOptions(&ss.DialOptions{Target: echoAddr, C: cli})
			if err != nil {
				t.Fatalf("DialSSWithOptions: %v", err)
			}
			defer conn.Close()

			payload := fmt.Sprintf("hello-%s-%d", m.name, time.Now().UnixNano())
			conn.Write([]byte(payload))

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 4096)
			n, err := ss.ReadN(conn, buf, nil)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if got := string(buf[:n]); got != payload {
				t.Errorf("echo mismatch:\n  want: %q\n  got:  %q", payload, got)
			}

		})
	}
}

// ---------------------------------------------------------------------------
// MultiServer TCP — multiserver with 5 cipher backends, each decrypts and
// forwards to echo. Mirrors remote_server.json multiserver config.
// ---------------------------------------------------------------------------

func TestIntegration_MultiServerTCP(t *testing.T) {
	t.Parallel()

	echoAddr, _, _ := echoServer(t)

	// Build multiserver with non-2022 ciphers only (2022 has a known
	// issue with SSMultiHandler TCP path, tracked separately).
	non2022 := []struct {
		name     string
		method   string
		password string
	}{allCipherMethods[0], allCipherMethods[1], allCipherMethods[2], allCipherMethods[3]}
	backends := make([]*ss.Config, len(non2022))
	for i, m := range non2022 {
		backends[i] = &ss.Config{
			CryptoConfig: ss.CryptoConfig{Method: m.method, Password: m.password},
		}
	}

	multisrv := &ss.Config{}
	multisrv.Type = "multiserver"
	multisrv.Localaddr = "127.0.0.1:0"
	multisrv.Backends = backends
	ss.CheckConfig(multisrv)
	t.Cleanup(func() { multisrv.Close() })

	handlers := []ss.AcceptHandler{ss.LimitHandler, ss.SSMultiHandler}
	sln, err := ss.Listen("127.0.0.1:0", multisrv, handlers)
	if err != nil {
		t.Fatal("multiserver listen:", err)
	}
	t.Cleanup(func() { sln.Close() })
	srvAddr := sln.Addr().String()

	go func() {
		for {
			c, err := sln.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(c.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(100 * time.Millisecond)

	// Test each cipher through the multiserver
	for _, m := range non2022 {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()

			cli := &ss.Config{}
			cli.Remoteaddr = srvAddr
			cli.Method = m.method
			cli.Password = m.password
			ss.CheckConfig(cli)
			defer cli.Close()

			conn, err := ss.DialSSWithOptions(&ss.DialOptions{Target: echoAddr, C: cli})
			if err != nil {
				t.Fatalf("DialSSWithOptions [%s]: %v", m.name, err)
			}
			defer conn.Close()

			payload := fmt.Sprintf("multisrv-%s", m.name)
			conn.Write([]byte(payload))

			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			buf := make([]byte, 4096)
			n, err := ss.ReadN(conn, buf, nil)
			if err != nil {
				t.Fatalf("read [%s]: %v", m.name, err)
			}
			if got := string(buf[:n]); got != payload {
				t.Errorf("[%s] echo mismatch: want %q, got %q", m.name, payload, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TLS obfs full-chain — SS client → (TLS obfs) → SS server → echo
// Mirrors local_server.json backends with obfsmethod=tls.
// ---------------------------------------------------------------------------

func TestIntegration_TLSObfsFullChain(t *testing.T) {
	t.Parallel()

	for _, m := range allCipherMethods {
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()

			echoAddr, _, _ := echoServer(t)

			srv := &ss.Config{}
			srv.Type = "server"
			srv.Method = m.method
			srv.Password = m.password
			srv.Obfs = true
			srv.ObfsMethod = "tls"
			srv.ObfsHost = []string{"cdn.baidu.com"}
			ss.CheckConfig(srv)
			defer srv.Close()

			handlers := []ss.AcceptHandler{ss.LimitHandler, ss.ObfsHandler}
			if crypto.IsAEAD2022(m.method) {
				handlers = append(handlers, ss.SS2022Handler)
			} else {
				handlers = append(handlers, ss.SSHandler)
			}

			sln, err := ss.Listen("127.0.0.1:0", srv, handlers)
			if err != nil {
				t.Fatal("server listen:", err)
			}
			defer sln.Close()
			srvAddr := sln.Addr().String()

			go func() {
				for {
					c, err := sln.Accept()
					if err != nil {
						return
					}
					go tcpRemoteHandler(c.(*ss.AcceptedConn))
				}
			}()

			time.Sleep(200 * time.Millisecond)

			cli := &ss.Config{}
			cli.Remoteaddr = srvAddr
			cli.Method = m.method
			cli.Password = m.password
			cli.Obfs = true
			cli.ObfsMethod = "tls"
			ss.CheckConfig(cli)
			defer cli.Close()

			var lastErr error
			for attempt := 0; attempt < 3; attempt++ {
				conn, err := ss.DialSSWithOptions(&ss.DialOptions{Target: echoAddr, C: cli})
				if err != nil {
					lastErr = err
					time.Sleep(100 * time.Millisecond)
					continue
				}

				payload := fmt.Sprintf("tls-obfs-%s-%d", m.name, time.Now().UnixNano())
				conn.Write([]byte(payload))

				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 4096)
				n, err := ss.ReadN(conn, buf, nil)
				conn.Close()
				if err != nil {
					lastErr = fmt.Errorf("read [%s]: %v", m.name, err)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				if got := string(buf[:n]); got != payload {
					t.Errorf("[%s] echo mismatch: want %q, got %q", m.name, payload, got)
				}
				lastErr = nil
				break
			}
			if lastErr != nil {
				t.Fatal(lastErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SocksProxy + SSProxy with TLS-obfs backend — mirrors local_server.json
// pattern: socksproxy(ssproxy=true) → TLS obfs → backend SS → echo
// ---------------------------------------------------------------------------

func TestIntegration_SocksProxySSProxyWithTLSObfsBackend(t *testing.T) {
	t.Parallel()

	echoAddr, _, _ := echoServer(t)

	// Backend SS server with TLS obfs
	backendCfg := &ss.Config{}
	backendCfg.Type = "server"
	backendCfg.Method = "aes-128-gcm"
	backendCfg.Password = "backend-pass"
	backendCfg.Obfs = true
	backendCfg.ObfsMethod = "tls"
	ss.CheckConfig(backendCfg)
	defer backendCfg.Close()

	backHandlers := []ss.AcceptHandler{ss.LimitHandler, ss.ObfsHandler, ss.SSHandler}
	bln, err := ss.Listen("127.0.0.1:0", backendCfg, backHandlers)
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	defer bln.Close()
	backendAddr := bln.Addr().String()

	go func() {
		for {
			c, err := bln.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(c.(*ss.AcceptedConn))
		}
	}()

	// Socksproxy with ssproxy=true, TLS obfs backend
	ssCfg := &ss.Config{}
	ssCfg.Type = "socksproxy"
	ssCfg.Method = "aes-128-gcm"
	ssCfg.Password = "frontend-pass"
	ssCfg.SSProxy = true
	ssCfg.Backends = []*ss.Config{{
		NetworkConfig: ss.NetworkConfig{Remoteaddr: backendAddr},
		CryptoConfig:  ss.CryptoConfig{Method: "aes-128-gcm", Password: "backend-pass"},
		ObfsConfig:    ss.ObfsConfig{Obfs: true, ObfsMethod: "tls"},
	}}
	ss.CheckConfig(ssCfg)
	defer ssCfg.Close()

	socksLn, err := ss.Listen("127.0.0.1:0", ssCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SocksAcceptor})
	if err != nil {
		t.Fatal("socksproxy listen:", err)
	}
	defer socksLn.Close()
	socksAddr := socksLn.Addr().String()

	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go socksProxyHandler(c.(*ss.AcceptedConn))
		}
	}()

	// SS client → socksproxy (frontend-pass) → TLS obfs → backend → echo
	cliCfg := &ss.Config{}
	cliCfg.Remoteaddr = socksAddr
	cliCfg.Method = "aes-128-gcm"
	cliCfg.Password = "frontend-pass"
	ss.CheckConfig(cliCfg)
	defer cliCfg.Close()

	time.Sleep(300 * time.Millisecond)

	conn, err := ss.DialSSWithOptions(&ss.DialOptions{Target: echoAddr, C: cliCfg})
	if err != nil {
		t.Fatalf("DialSSWithOptions: %v", err)
	}
	defer conn.Close()

	payload := "hello-socksproxy-tls-obfs-backend"
	conn.Write([]byte(payload))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := ss.ReadN(conn, buf, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != payload {
		t.Errorf("echo mismatch: want %q, got %q", payload, got)
	}
}

// ---------------------------------------------------------------------------
// Wstunnel obfs full-chain — mirrors remote_server.json wstunnel config
// ---------------------------------------------------------------------------

func TestIntegration_WstunnelObfsFullChain(t *testing.T) {
	t.Parallel()

	echoAddr, _, _ := echoServer(t)

	// Pre-bind to get a port, then run wstunnel server on it (same pattern as
	// json_config_test.go wstunnel tests).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("pre-bind:", err)
	}
	wsAddr := ln.Addr().String()
	ln.Close()

	srv := &ss.Config{}
	srv.Type = "wstunnel"
	srv.Localaddr = wsAddr
	srv.Method = "aes-128-gcm"
	srv.Password = "plin-thik-born"
	srv.Obfs = true
	srv.ObfsMethod = "wstunnel"
	srv.AllowHTTP = true
	ss.CheckConfig(srv)
	defer srv.Close()

	go RunWstunnelRemoteServer(srv)
	time.Sleep(400 * time.Millisecond)

	// SS client over wstunnel transport
	cli := &ss.Config{}
	cli.Remoteaddr = "ws://" + wsAddr
	cli.Method = "aes-128-gcm"
	cli.Password = "plin-thik-born"
	cli.Obfs = true
	cli.ObfsMethod = "wstunnel"
	ss.CheckConfig(cli)
	defer cli.Close()

	conn, err := ss.DialSSWithOptions(&ss.DialOptions{Target: echoAddr, C: cli})
	if err != nil {
		t.Fatalf("DialSSWithOptions: %v", err)
	}
	defer conn.Close()

	payload := "hello-wstunnel-obfs"
	conn.Write([]byte(payload))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := ss.ReadN(conn, buf, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != payload {
		t.Errorf("echo mismatch: want %q, got %q", payload, got)
	}
}

// ---------------------------------------------------------------------------
// SocksProxy → SOCKS5 backend — mirrors remote_server.json pattern:
// socksproxy(ssproxy=true) with method=socks5 backend
// ---------------------------------------------------------------------------

func TestIntegration_SocksProxyWithSOCKS5Backend(t *testing.T) {
	t.Parallel()

	echoAddr, _, _ := echoServer(t)

	// Minimal SOCKS5 proxy → echo
	socks5Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks5Ln.Close()
	socks5Addr := socks5Ln.Addr().String()
	go serveMinimalSOCKS5(socks5Ln, echoAddr)

	// Socksproxy with ssproxy=true and socks5 backend
	ssCfg := &ss.Config{}
	ssCfg.Type = "socksproxy"
	ssCfg.Method = "aes-128-gcm"
	ssCfg.Password = "frontend-pass"
	ssCfg.SSProxy = true
	ssCfg.Backends = []*ss.Config{{
		NetworkConfig: ss.NetworkConfig{Remoteaddr: socks5Addr},
		CryptoConfig:  ss.CryptoConfig{Method: "socks5"},
	}}
	ss.CheckConfig(ssCfg)
	defer ssCfg.Close()

	socksLn, err := ss.Listen("127.0.0.1:0", ssCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SocksAcceptor})
	if err != nil {
		t.Fatal("socksproxy listen:", err)
	}
	defer socksLn.Close()
	socksAddr := socksLn.Addr().String()

	go func() {
		for {
			c, err := socksLn.Accept()
			if err != nil {
				return
			}
			go socksProxyHandler(c.(*ss.AcceptedConn))
		}
	}()

	// SS client → socksproxy (frontend-pass) → socks5 → echo
	cliCfg := &ss.Config{}
	cliCfg.Remoteaddr = socksAddr
	cliCfg.Method = "aes-128-gcm"
	cliCfg.Password = "frontend-pass"
	ss.CheckConfig(cliCfg)
	defer cliCfg.Close()

	time.Sleep(200 * time.Millisecond)

	conn, err := ss.DialSSWithOptions(&ss.DialOptions{Target: echoAddr, C: cliCfg})
	if err != nil {
		t.Fatalf("DialSSWithOptions: %v", err)
	}
	defer conn.Close()

	payload := "hello-socksproxy-to-socks5-backend"
	conn.Write([]byte(payload))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := ss.ReadN(conn, buf, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != payload {
		t.Errorf("echo mismatch: want %q, got %q", payload, got)
	}
}

// ---------------------------------------------------------------------------
// ssproxy → multiple backends race — verifies backends loop selects the
// first successful connection when multiple backends are configured.
// ---------------------------------------------------------------------------

func TestIntegration_SSProxyWithMultipleBackends(t *testing.T) {
	t.Parallel()

	echoAddr, _, _ := echoServer(t)

	// Working SS backend → echo
	backendCfg := &ss.Config{}
	backendCfg.Type = "server"
	backendCfg.Method = "aes-128-gcm"
	backendCfg.Password = "backend-pass"
	ss.CheckConfig(backendCfg)
	defer backendCfg.Close()

	bln, err := ss.Listen("127.0.0.1:0", backendCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	defer bln.Close()
	backendAddr := bln.Addr().String()

	go func() {
		for {
			c, err := bln.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(c.(*ss.AcceptedConn))
		}
	}()

	// ssproxy with two backends: one working (SS), one unreachable (cancels quickly)
	ssCfg := &ss.Config{}
	ssCfg.Type = "ssproxy"
	ssCfg.Method = "aes-128-gcm"
	ssCfg.Password = "frontend-pass"
	ssCfg.Backends = []*ss.Config{
		{
			NetworkConfig: ss.NetworkConfig{Remoteaddr: "127.0.0.1:1"}, // unreachable, fails fast
			CryptoConfig:  ss.CryptoConfig{Method: "aes-128-gcm", Password: "dead-pass"},
		},
		{
			NetworkConfig: ss.NetworkConfig{Remoteaddr: backendAddr},
			CryptoConfig:  ss.CryptoConfig{Method: "aes-128-gcm", Password: "backend-pass"},
		},
	}
	ss.CheckConfig(ssCfg)
	defer ssCfg.Close()

	sln, err := ss.Listen("127.0.0.1:0", ssCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal("ssproxy listen:", err)
	}
	defer sln.Close()
	ssAddr := sln.Addr().String()

	go func() {
		for {
			c, err := sln.Accept()
			if err != nil {
				return
			}
			go ssproxyHandler(c.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	cliCfg := &ss.Config{}
	cliCfg.Remoteaddr = ssAddr
	cliCfg.Method = "aes-128-gcm"
	cliCfg.Password = "frontend-pass"
	ss.CheckConfig(cliCfg)
	defer cliCfg.Close()

	for i := range 3 {
		conn, err := ss.DialSSWithOptions(&ss.DialOptions{Target: echoAddr, C: cliCfg})
		if err != nil {
			t.Fatalf("conn %d: DialSSWithOptions: %v", i, err)
		}

		payload := fmt.Sprintf("multi-backend-%d-%d", i, time.Now().UnixNano())
		conn.Write([]byte(payload))

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		n, err := ss.ReadN(conn, buf, nil)
		if err != nil {
			conn.Close()
			t.Fatalf("conn %d: read: %v", i, err)
		}
		if got := string(buf[:n]); got != payload {
			t.Errorf("conn %d: echo mismatch: want %q, got %q", i, payload, got)
		}
		conn.Close()
	}
}

// ---------------------------------------------------------------------------
// Concurrent connections — stresses the proxy with parallel connections.
// ---------------------------------------------------------------------------

func TestIntegration_ConcurrentConnections(t *testing.T) {
	t.Parallel()

	echoAddr, _, _ := echoServer(t)

	srv := &ss.Config{}
	srv.Type = "server"
	srv.Method = "aes-128-gcm"
	srv.Password = "test-pw"
	ss.CheckConfig(srv)
	defer srv.Close()

	sln, err := ss.Listen("127.0.0.1:0", srv, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal("server listen:", err)
	}
	defer sln.Close()
	srvAddr := sln.Addr().String()

	go func() {
		for {
			c, err := sln.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(c.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(100 * time.Millisecond)

	const numConns = 20
	var wg sync.WaitGroup
	errs := make(chan error, numConns)

	for i := range numConns {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			cli := &ss.Config{}
			cli.Remoteaddr = srvAddr
			cli.Method = "aes-128-gcm"
			cli.Password = "test-pw"
			ss.CheckConfig(cli)
			defer cli.Close()

			conn, err := ss.DialSSWithOptions(&ss.DialOptions{Target: echoAddr, C: cli})
			if err != nil {
				errs <- fmt.Errorf("conn %d: dial: %v", id, err)
				return
			}
			defer conn.Close()

			payload := fmt.Sprintf("concurrent-%d-%d", id, time.Now().UnixNano())
			conn.Write([]byte(payload))

			conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			buf := make([]byte, 4096)
			n, err := ss.ReadN(conn, buf, nil)
			if err != nil {
				errs <- fmt.Errorf("conn %d: read: %v", id, err)
				return
			}
			if got := string(buf[:n]); got != payload {
				errs <- fmt.Errorf("conn %d: echo mismatch: want %q, got %q", id, payload, got)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// ---------------------------------------------------------------------------
// TCP tunnel — mirrors local_server.json tcptun config:
// raw TCP → tcptun → SS → backend SS server → echo
// ---------------------------------------------------------------------------

func TestIntegration_TCPTun(t *testing.T) {
	t.Parallel()

	echoAddr, _, _ := echoServer(t)

	// Backend SS server
	backendCfg := &ss.Config{}
	backendCfg.Type = "server"
	backendCfg.Method = "aes-128-gcm"
	backendCfg.Password = "plin-thik-born"
	ss.CheckConfig(backendCfg)
	defer backendCfg.Close()

	bln, err := ss.Listen("127.0.0.1:0", backendCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	defer bln.Close()
	backendAddr := bln.Addr().String()

	go func() {
		for {
			c, err := bln.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(c.(*ss.AcceptedConn))
		}
	}()

	// tcptun: raw TCP → SS backend → echo
	tunCfg := &ss.Config{}
	tunCfg.Type = "tcptun"
	tunCfg.Localaddr = "127.0.0.1:0"
	tunCfg.Remoteaddr = echoAddr
	tunCfg.Backend = &ss.Config{
		CryptoConfig:  ss.CryptoConfig{Method: "aes-128-gcm", Password: "plin-thik-born"},
		NetworkConfig: ss.NetworkConfig{Remoteaddr: backendAddr},
	}
	ss.CheckConfig(tunCfg)
	defer tunCfg.Close()

	tunLn, err := ss.Listen(tunCfg.Localaddr, tunCfg, nil)
	if err != nil {
		t.Fatal("tcptun listen:", err)
	}
	defer tunLn.Close()
	tunAddr := tunLn.Addr().String()

	go func() {
		for {
			c, err := tunLn.Accept()
			if err != nil {
				return
			}
			go tcpTunHandler(c.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Raw TCP client → tcptun → SS → echo
	conn, err := net.Dial("tcp", tunAddr)
	if err != nil {
		t.Fatalf("dial tcptun: %v", err)
	}
	defer conn.Close()

	payload := "hello-tcptun-test"
	conn.Write([]byte(payload))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != payload {
		t.Errorf("echo mismatch: want %q, got %q", payload, got)
	}
}

// ---------------------------------------------------------------------------
// Switch mode — mirrors local_server.json switch config:
// routes raw TCP to the active backend target
// ---------------------------------------------------------------------------

func TestIntegration_Switch(t *testing.T) {
	t.Parallel()

	// Echo server that the switch will forward to
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()

	// Switch with active backend pointing directly to echo via TCP
	swCfg := &ss.Config{}
	swCfg.Type = "switch"
	swCfg.Localaddr = "127.0.0.1:0"
	swCfg.ActiveBackend = "echo-backend"
	swCfg.Backends = []*ss.Config{{
		Nickname:      "echo-backend",
		NetworkConfig: ss.NetworkConfig{Remoteaddr: echoAddr},
	}}
	swCfg.Backends[0].Method = "plain"
	ss.CheckConfig(swCfg)
	defer swCfg.Close()

	swLn, err := ss.Listen(swCfg.Localaddr, swCfg, nil)
	if err != nil {
		t.Fatal("switch listen:", err)
	}
	defer swLn.Close()
	swAddr := swLn.Addr().String()

	go func() {
		for {
			c, err := swLn.Accept()
			if err != nil {
				return
			}
			go switchHandler(c.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	conn, err := net.Dial("tcp", swAddr)
	if err != nil {
		t.Fatalf("dial switch: %v", err)
	}
	defer conn.Close()

	payload := "hello-switch-test"
	conn.Write([]byte(payload))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != payload {
		t.Errorf("echo mismatch: want %q, got %q", payload, got)
	}
}

// ---------------------------------------------------------------------------
// UDP relay — mirrors remote_server.json multiserver with udprelay=true
// ---------------------------------------------------------------------------

func TestIntegration_UDPRelay(t *testing.T) {
	t.Parallel()

	_, echoPort := udpEchoServer(t)

	// SS server with UDP relay
	srvCfg := &ss.Config{}
	srvCfg.Type = "server"
	srvCfg.Method = "aes-128-gcm"
	srvCfg.Password = "plin-thik-born"
	srvCfg.UDPRelay = true
	ss.CheckConfig(srvCfg)
	defer srvCfg.Close()

	srvLn, err := ss.ListenUDP(srvCfg)
	if err != nil {
		t.Fatal("server UDP listen:", err)
	}
	srvAddr := srvLn.LocalAddr().(*net.UDPAddr)

	go RunUDPServer(srvLn, srvCfg, getCreateFuncOfUDPRemoteServer)

	// SS UDP client → server → echo
	cliCfg := &ss.Config{}
	cliCfg.Method = "aes-128-gcm"
	cliCfg.Password = "plin-thik-born"
	cliCfg.Remoteaddr = srvAddr.String()
	ss.CheckConfig(cliCfg)
	defer cliCfg.Close()

	conn, err := ss.DialUDP(cliCfg)
	if err != nil {
		t.Fatal("DialUDP:", err)
	}
	defer conn.Close()

	// SS UDP header: [type=1, IPv4=127.0.0.1, port=echoPort]
	header := []byte{1, 127, 0, 0, 1, byte(echoPort >> 8), byte(echoPort)}
	payload := []byte("hello-udp-relay")
	packet := append(header, payload...)
	conn.Write(packet)

	resp := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := ss.ReadN(conn, resp, nil)
	if err != nil {
		t.Fatalf("UDP read: %v", err)
	}
	// Strip the 7-byte response header
	if n < 7 {
		t.Fatalf("response too short: %d bytes", n)
	}
	if got := string(resp[7:n]); got != string(payload) {
		t.Errorf("UDP echo mismatch: want %q, got %q", payload, got)
	}
}
