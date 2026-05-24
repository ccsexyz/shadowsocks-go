package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/gorilla/websocket"
)

// TestWithJSONConfig_VirtualSocksChain tests a virtual SOCKS proxy using
// the exact same JSON config a user would write.
func TestWithJSONConfig_VirtualSocksChain(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	configJSON := `[
		{
			"type": "server",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "test123"
		},
		{
			"type": "local",
			"localaddr": "@vsocks",
			"remoteaddr": "SERVER_ADDR",
			"method": "aes-256-gcm",
			"password": "test123"
		}
	]`

	cfgs := parseConfigs(t, configJSON)
	srvCfg, cliCfg := cfgs[0], cfgs[1]

	// Start server — need to get its actual address for the client config
	srvLn, err := ss.Listen("127.0.0.1:0", srvCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal("server listen:", err)
	}
	defer srvLn.Close()
	defer srvCfg.Close()

	srvAddr := srvLn.Addr().String()
	cliCfg.Remoteaddr = srvAddr

	go func() {
		for {
			conn, err := srvLn.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(conn.(*ss.AcceptedConn))
		}
	}()

	go RunTCPLocalServer(cliCfg)
	defer cliCfg.Close()

	time.Sleep(200 * time.Millisecond)

	// Dial the virtual SOCKS proxy
	client, err := ss.DialVirtual("@vsocks")
	if err != nil {
		t.Fatalf("DialVirtual @vsocks: %v", err)
	}
	defer client.Close()

	socks5Connect(t, client, echoHost, echoPort)

	payload := "hello-json-config-vsocks"
	client.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(client, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}

	// Verify virtual service listing
	verifyVirtualService(t, "@vsocks", "local-@vsocks")
}

// TestWithJSONConfig_RtunnelVirtualService tests the reverse tunnel with
// a virtual service address, using real JSON config format.
func TestWithJSONConfig_RtunnelVirtualService(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	configJSON := `[
		{
			"type": "rtunnelserver",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "test123",
			"rtunnelservice": "@rtun-web"
		},
		{
			"type": "rtunnelclient",
			"remoteaddr": "ECHO_ADDR",
			"backend": {
				"remoteaddr": "SERVER_ADDR",
				"method": "aes-256-gcm",
				"password": "test123"
			}
		}
	]`

	cfgs := parseConfigs(t, configJSON)
	srvCfg, cliCfg := cfgs[0], cfgs[1]

	// Set up rtunnel server
	handlers := []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler}
	srvLn, err := ss.Listen("127.0.0.1:0", srvCfg, handlers)
	if err != nil {
		t.Fatal("server listen:", err)
	}
	defer srvLn.Close()
	defer srvCfg.Close()

	serverAddr := srvLn.Addr().String()
	cliCfg.Backend.Remoteaddr = serverAddr
	cliCfg.Remoteaddr = net.JoinHostPort(echoHost, strconv.Itoa(echoPort))

	go func() {
		for {
			conn, err := srvLn.Accept()
			if err != nil {
				return
			}
			go rtunnelServerHandler(conn.(*ss.AcceptedConn))
		}
	}()

	go RunRtunnelClient(cliCfg)
	defer cliCfg.Close()

	// Need to wait for smux keepalive to flush the non-2022 SS wremain
	time.Sleep(2 * time.Second)

	verifyVirtualService(t, "@rtun-web", srvCfg.Nickname)

	conn, err := ss.DialVirtual("@rtun-web")
	if err != nil {
		t.Fatalf("DialVirtual @rtun-web: %v", err)
	}
	defer conn.Close()

	payload := "hello-rtunnel-json"
	conn.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(conn, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}
}

// TestWithJSONConfig_MultiBackendRtunnel tests the fix for per-backend
// rtunnelservice routing. Each backend exposes a different virtual service.
func TestWithJSONConfig_MultiBackendRtunnel(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	configJSON := `[
		{
			"type": "rtunnelserver",
			"localaddr": "127.0.0.1:0",
			"backends": [
				{
					"method": "aes-256-gcm",
					"password": "bob-secret",
					"rtunnelservice": "@tunnel-bob"
				},
				{
					"method": "chacha20poly1305",
					"password": "alice-key",
					"rtunnelservice": "@tunnel-alice"
				}
			]
		},
		{
			"type": "rtunnelclient",
			"remoteaddr": "ECHO_ADDR",
			"backend": {
				"remoteaddr": "SERVER_ADDR",
				"method": "aes-256-gcm",
				"password": "bob-secret"
			}
		},
		{
			"type": "rtunnelclient",
			"remoteaddr": "ECHO_ADDR",
			"backend": {
				"remoteaddr": "SERVER_ADDR",
				"method": "chacha20poly1305",
				"password": "alice-key"
			}
		}
	]`

	cfgs := parseConfigs(t, configJSON)
	srvCfg := cfgs[0]
	bobCli := cfgs[1]
	aliceCli := cfgs[2]

	handlers := []ss.AcceptHandler{ss.LimitHandler, ss.SSMultiHandler}
	srvLn, err := ss.Listen("127.0.0.1:0", srvCfg, handlers)
	if err != nil {
		t.Fatal("server listen:", err)
	}
	defer srvLn.Close()
	defer srvCfg.Close()

	serverAddr := srvLn.Addr().String()
	targetAddr := net.JoinHostPort(echoHost, strconv.Itoa(echoPort))

	bobCli.Backend.Remoteaddr = serverAddr
	bobCli.Remoteaddr = targetAddr
	aliceCli.Backend.Remoteaddr = serverAddr
	aliceCli.Remoteaddr = targetAddr

	go func() {
		for {
			conn, err := srvLn.Accept()
			if err != nil {
				return
			}
			go rtunnelServerHandler(conn.(*ss.AcceptedConn))
		}
	}()

	go RunRtunnelClient(bobCli)
	defer bobCli.Close()
	go RunRtunnelClient(aliceCli)
	defer aliceCli.Close()

	time.Sleep(2 * time.Second)

	// Both virtual services should be registered
	verifyVirtualService(t, "@tunnel-bob", srvCfg.Backends[0].Nickname)
	verifyVirtualService(t, "@tunnel-alice", srvCfg.Backends[1].Nickname)

	// Test Bob's tunnel
	t.Run("bob", func(t *testing.T) {
		conn, err := ss.DialVirtual("@tunnel-bob")
		if err != nil {
			t.Fatalf("DialVirtual @tunnel-bob: %v", err)
		}
		defer conn.Close()
		payload := "bob-data"
		conn.Write([]byte(payload))
		resp := make([]byte, len(payload))
		io.ReadFull(conn, resp)
		if string(resp) != payload {
			t.Errorf("expected '%s', got '%s'", payload, string(resp))
		}
	})

	// Test Alice's tunnel
	t.Run("alice", func(t *testing.T) {
		conn, err := ss.DialVirtual("@tunnel-alice")
		if err != nil {
			t.Fatalf("DialVirtual @tunnel-alice: %v", err)
		}
		defer conn.Close()
		payload := "alice-data"
		conn.Write([]byte(payload))
		resp := make([]byte, len(payload))
		io.ReadFull(conn, resp)
		if string(resp) != payload {
			t.Errorf("expected '%s', got '%s'", payload, string(resp))
		}
	})
}

// TestWithJSONConfig_AdminAPI tests the admin API for virtual service listing,
// matching what curl would see.
func TestWithJSONConfig_AdminAPI(t *testing.T) {
	configJSON := `[
		{
			"type": "server",
			"localaddr": "@admin-srv",
			"method": "aes-256-gcm",
			"password": "test"
		},
		{
			"type": "local",
			"localaddr": "@admin-cli",
			"remoteaddr": "@admin-srv",
			"method": "aes-256-gcm",
			"password": "test"
		}
	]`

	cfgs := parseConfigs(t, configJSON)
	srvCfg, cliCfg := cfgs[0], cfgs[1]

	go RunTCPRemoteServer(srvCfg)
	defer srvCfg.Close()
	go RunTCPLocalServer(cliCfg)
	defer cliCfg.Close()

	time.Sleep(200 * time.Millisecond)

	// Simulate what GET /api/virtual returns
	services := ss.ListVirtualServices()

	if len(services) < 2 {
		t.Errorf("expected at least 2 virtual services, got %d", len(services))
	}

	found := make(map[string]bool)
	for _, s := range services {
		found[s.Name] = true
		t.Logf("virtual service: name=%s source=%s accepts=%d",
			s.Name, s.Source, s.AcceptCount)
	}

	for _, name := range []string{"@admin-srv", "@admin-cli"} {
		if !found[name] {
			t.Errorf("virtual service %s not found in listing", name)
		}
	}

	// Test actual data flow through the chain
	_, echoHost, echoPort := echoServer(t)

	client, err := ss.DialVirtual("@admin-cli")
	if err != nil {
		t.Fatalf("DialVirtual @admin-cli: %v", err)
	}
	defer client.Close()

	socks5Connect(t, client, echoHost, echoPort)

	payload := "admin-api-test"
	client.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(client, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}

	// AcceptCount should have increased
	services = ss.ListVirtualServices()
	for _, s := range services {
		if s.Name == "@admin-cli" && s.AcceptCount < 1 {
			t.Errorf("@admin-cli AcceptCount should be >= 1, got %d", s.AcceptCount)
		}
	}
}

// TestWithJSONConfig_SSProxyVirtualBackend tests ssproxy where the backend
// is a virtual SS server — the exact JSON config a user would write.
func TestWithJSONConfig_SSProxyVirtualBackend(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	configJSON := `[
		{
			"type": "server",
			"localaddr": "@virt-backend",
			"method": "aes-256-gcm",
			"password": "backend-pass"
		},
		{
			"type": "ssproxy",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "frontend-pass",
			"backend": {
				"remoteaddr": "@virt-backend",
				"method": "aes-256-gcm",
				"password": "backend-pass"
			}
		}
	]`

	cfgs := parseConfigs(t, configJSON)
	backendCfg, proxyCfg := cfgs[0], cfgs[1]

	go RunTCPRemoteServer(backendCfg)
	defer backendCfg.Close()

	handlers := []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler}
	proxyLn, err := ss.Listen("127.0.0.1:0", proxyCfg, handlers)
	if err != nil {
		t.Fatal("proxy listen:", err)
	}
	defer proxyLn.Close()
	defer proxyCfg.Close()

	proxyAddr := proxyLn.Addr().String()

	go func() {
		for {
			conn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			go ssproxyHandler(conn.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Connect as SS client to the proxy, targeting the echo server
	cli := &ss.Config{}
	cli.Method = "aes-256-gcm"
	cli.Password = "frontend-pass"
	cli.Remoteaddr = proxyAddr
	ss.CheckConfig(cli)
	defer cli.Close()

	rconn, err := ss.DialSSWithOptions(&ss.DialOptions{
		Target: net.JoinHostPort(echoHost, strconv.Itoa(echoPort)),
		C:      cli,
	})
	if err != nil {
		t.Fatalf("DialSSWithOptions: %v", err)
	}
	defer rconn.Close()

	payload := "ssproxy-virt-backend"
	rconn.Write([]byte(payload))
	resp := make([]byte, len(payload))
	ss.ReadN(rconn, resp, nil)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}

	verifyVirtualService(t, "@virt-backend", backendCfg.Nickname)
}

// TestWithJSONConfig_MultipleVirtualServicesConcurrently runs multiple
// independent virtual services concurrently with different configs.
func TestWithJSONConfig_MultipleVirtualServicesConcurrently(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	const numServices = 3
	type pipe struct {
		srv  *ss.Config
		cli  *ss.Config
		name string
	}

	var pipes []pipe
	for i := range numServices {
		srv := &ss.Config{}
		srv.Type = "server"
		srv.Localaddr = "@multi-srv-" + strconv.Itoa(i)
		srv.Method = "aes-256-gcm"
		srv.Password = "pass-" + strconv.Itoa(i)
		ss.CheckConfig(srv)

		cli := &ss.Config{}
		cli.Type = "local"
		cli.Localaddr = "@multi-cli-" + strconv.Itoa(i)
		cli.Remoteaddr = srv.Localaddr
		cli.Method = srv.Method
		cli.Password = srv.Password
		ss.CheckConfig(cli)

		go RunTCPRemoteServer(srv)
		go RunTCPLocalServer(cli)

		pipes = append(pipes, pipe{srv, cli, "@multi-cli-" + strconv.Itoa(i)})
	}
	defer func() {
		for _, p := range pipes {
			p.srv.Close()
			p.cli.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)

	// Verify all appear in listing
	services := ss.ListVirtualServices()
	found := make(map[string]bool)
	for _, s := range services {
		found[s.Name] = true
	}
	for _, p := range pipes {
		if !found[p.name] {
			t.Errorf("%s not in virtual service listing", p.name)
		}
	}

	// Test all concurrently
	var wg sync.WaitGroup
	for i, p := range pipes {
		wg.Add(1)
		go func(id int, name string) {
			defer wg.Done()
			conn, err := ss.DialVirtual(name)
			if err != nil {
				t.Errorf("%s: DialVirtual: %v", name, err)
				return
			}
			defer conn.Close()

			socks5Connect(t, conn, echoHost, echoPort)

			payload := []byte("data-" + strconv.Itoa(id))
			conn.Write(payload)
			resp := make([]byte, len(payload))
			io.ReadFull(conn, resp)
			if string(resp) != string(payload) {
				t.Errorf("%s: expected '%s', got '%s'", name, payload, string(resp))
			}
		}(i, p.name)
	}
	wg.Wait()
}

// TestWithJSONConfig_TargetMapWSRouting tests that a wstunnel server with
// target_map routes WebSocket connections based on the Host header.
func TestWithJSONConfig_TargetMapWSRouting(t *testing.T) {
	echoAddr, _, _ := echoServer(t)

	configJSON := fmt.Sprintf(`[
		{
			"type": "wstunnel",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "test",
			"allow_http": true,
			"target_map": {
				"myhost.example.com": %q
			}
		}
	]`, echoAddr)

	cfgs := parseConfigs(t, configJSON)
	wsCfg := cfgs[0]

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen:", err)
	}
	wsAddr := ln.Addr().String()
	ln.Close()
	wsCfg.Localaddr = wsAddr

	go RunWstunnelRemoteServer(wsCfg)
	defer wsCfg.Close()
	time.Sleep(300 * time.Millisecond)

	dialer := websocket.Dialer{}
	header := http.Header{}
	header.Set("Host", "myhost.example.com")

	wsURL := "ws://" + wsAddr + "/"
	conn, _, err := dialer.Dial(wsURL, header)
	if err != nil {
		t.Fatalf("WebSocket dial: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-target-map-ws")
	if err := conn.WriteMessage(websocket.BinaryMessage, payload); err != nil {
		t.Fatalf("WS write: %v", err)
	}

	_, resp, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("WS read: %v", err)
	}
	if string(resp) != string(payload) {
		t.Errorf("expected '%s', got '%s'", payload, resp)
	}
}

// TestWithJSONConfig_TargetMapHTTPProxy tests that a wstunnel server with
// target_map proxies non-WebSocket HTTP requests to the configured target.
func TestWithJSONConfig_TargetMapHTTPProxy(t *testing.T) {
	// Start a simple HTTP backend
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	backendMux := http.NewServeMux()
	backendMux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("backend-response-ok"))
	})
	backendSrv := &http.Server{Handler: backendMux}
	go backendSrv.Serve(backendLn)
	defer backendSrv.Close()

	configJSON := fmt.Sprintf(`[
		{
			"type": "wstunnel",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "test",
			"allow_http": true,
			"target_map": {
				"http_proxy_to": %q
			}
		}
	]`, backendAddr)

	cfgs := parseConfigs(t, configJSON)
	wsCfg := cfgs[0]

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen:", err)
	}
	wsAddr := ln.Addr().String()
	ln.Close()
	wsCfg.Localaddr = wsAddr

	go RunWstunnelRemoteServer(wsCfg)
	defer wsCfg.Close()
	time.Sleep(300 * time.Millisecond)

	// Send a plain HTTP request (not WS upgrade) to the wstunnel server
	req, err := http.NewRequest("GET", "http://"+wsAddr+"/test", nil)
	if err != nil {
		t.Fatal("new request:", err)
	}
	req.Host = backendAddr

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "backend-response-ok" {
		t.Errorf("expected 'backend-response-ok', got '%s' (status %d)", body, resp.StatusCode)
	}
}

// TestWithJSONConfig_TargetMapHeaderRouting tests that HTTP requests are
// routed by header values in target_map. The Host header points to a
// non-existent address so the test fails if target routing is broken.
func TestWithJSONConfig_TargetMapHeaderRouting(t *testing.T) {
	backend := startHTTPBackend(t)
	defer backend.Close()
	backendAddr := backend.Addr

	configJSON := fmt.Sprintf(`[
		{
			"type": "wstunnel",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "test",
			"allow_http": true,
			"target_map": {
				"API-KEY test-token": %q
			}
		}
	]`, backendAddr)

	cfgs := parseConfigs(t, configJSON)
	wsCfg := cfgs[0]

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen:", err)
	}
	wsAddr := ln.Addr().String()
	ln.Close()
	wsCfg.Localaddr = wsAddr

	go RunWstunnelRemoteServer(wsCfg)
	defer wsCfg.Close()
	time.Sleep(300 * time.Millisecond)

	// Host is a BOGUS address — if routing is broken, connection fails.
	req, err := http.NewRequest("GET", "http://"+wsAddr+"/test", nil)
	if err != nil {
		t.Fatal("new request:", err)
	}
	req.Host = "bogus-host.invalid:9999"
	req.Header.Set("api-key", "test-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request (route via api-key header): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d (body=%s, x-error=%s)",
			resp.StatusCode, body, resp.Header.Get("X-Error-Info"))
	}
}

// TestWithJSONConfig_TargetMapHeaderCaseInsensitive verifies that
// HTTP header value matching is case-insensitive (RFC 7230 §3.2).
func TestWithJSONConfig_TargetMapHeaderCaseInsensitive(t *testing.T) {
	backend := startHTTPBackend(t)
	defer backend.Close()
	backendAddr := backend.Addr

	configJSON := fmt.Sprintf(`[
		{
			"type": "wstunnel",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "test",
			"allow_http": true,
			"target_map": {
				"x-custom-route secret-value": %q
			}
		}
	]`, backendAddr)

	cfgs := parseConfigs(t, configJSON)
	wsCfg := cfgs[0]

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen:", err)
	}
	wsAddr := ln.Addr().String()
	ln.Close()
	wsCfg.Localaddr = wsAddr

	go RunWstunnelRemoteServer(wsCfg)
	defer wsCfg.Close()
	time.Sleep(300 * time.Millisecond)

	cases := []struct {
		name       string
		headerName string
		headerVal  string
	}{
		{"exact match", "x-custom-route", "secret-value"},
		{"value uppercase", "x-custom-route", "SECRET-VALUE"},
		{"value mixed case", "x-custom-route", "Secret-Value"},
		{"name canonical", "X-Custom-Route", "secret-value"},
		{"both mixed case", "X-Custom-Route", "Secret-Value"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "http://"+wsAddr+"/test", nil)
			if err != nil {
				t.Fatal("new request:", err)
			}
			req.Host = "bogus-host.invalid:9999"
			req.Header.Set(tc.headerName, tc.headerVal)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("HTTP request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != 200 {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("expected 200, got %d (body=%s, x-error=%s)",
					resp.StatusCode, body, resp.Header.Get("X-Error-Info"))
			}
		})
	}
}

// TestWithJSONConfig_TargetMapMethodURIRouting tests routing by
// "METHOD /path" entries in target_map.
func TestWithJSONConfig_TargetMapMethodURIRouting(t *testing.T) {
	backend := startHTTPBackend(t)
	defer backend.Close()
	backendAddr := backend.Addr

	configJSON := fmt.Sprintf(`[
		{
			"type": "wstunnel",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "test",
			"allow_http": true,
			"target_map": {
				"GET /special-path": %q
			}
		}
	]`, backendAddr)

	cfgs := parseConfigs(t, configJSON)
	wsCfg := cfgs[0]

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen:", err)
	}
	wsAddr := ln.Addr().String()
	ln.Close()
	wsCfg.Localaddr = wsAddr

	go RunWstunnelRemoteServer(wsCfg)
	defer wsCfg.Close()
	time.Sleep(300 * time.Millisecond)

	req, err := http.NewRequest("GET", "http://"+wsAddr+"/special-path", nil)
	if err != nil {
		t.Fatal("new request:", err)
	}
	req.Host = "another-bogus.invalid:9999"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request (route via method+URI): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d (body=%s)", resp.StatusCode, body)
	}
}

// TestWithJSONConfig_TargetMapNoMatch403 tests that requests without any
// matching target_map entry and no http_proxy_to fallback get a 403.
func TestWithJSONConfig_TargetMapNoMatch403(t *testing.T) {
	configJSON := `[
		{
			"type": "wstunnel",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "test",
			"allow_http": true,
			"target_map": {}
		}
	]`

	cfgs := parseConfigs(t, configJSON)
	wsCfg := cfgs[0]

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen:", err)
	}
	wsAddr := ln.Addr().String()
	ln.Close()
	wsCfg.Localaddr = wsAddr

	go RunWstunnelRemoteServer(wsCfg)
	defer wsCfg.Close()
	time.Sleep(300 * time.Millisecond)

	req, err := http.NewRequest("GET", "http://"+wsAddr+"/test", nil)
	if err != nil {
		t.Fatal("new request:", err)
	}
	req.Host = "no-match.invalid:9999"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Errorf("expected 403, got %d", resp.StatusCode)
	}
}

// TestWithJSONConfig_TargetMapFallbackHTTPProxyTo tests the http_proxy_to
// fallback when no header or method+URI match exists.
func TestWithJSONConfig_TargetMapFallbackHTTPProxyTo(t *testing.T) {
	backend := startHTTPBackend(t)
	defer backend.Close()
	backendAddr := backend.Addr

	configJSON := fmt.Sprintf(`[
		{
			"type": "wstunnel",
			"localaddr": "127.0.0.1:0",
			"method": "aes-256-gcm",
			"password": "test",
			"allow_http": true,
			"target_map": {
				"http_proxy_to": %q
			}
		}
	]`, backendAddr)

	cfgs := parseConfigs(t, configJSON)
	wsCfg := cfgs[0]

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen:", err)
	}
	wsAddr := ln.Addr().String()
	ln.Close()
	wsCfg.Localaddr = wsAddr

	go RunWstunnelRemoteServer(wsCfg)
	defer wsCfg.Close()
	time.Sleep(300 * time.Millisecond)

	req, err := http.NewRequest("GET", "http://"+wsAddr+"/test", nil)
	if err != nil {
		t.Fatal("new request:", err)
	}
	req.Host = "fallback-test.invalid:9999"

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request (fallback http_proxy_to): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d (body=%s)", resp.StatusCode, body)
	}
}

// httpBackend is a test HTTP server with its listener address.
type httpBackend struct {
	*http.Server
	Addr string
}

// startHTTPBackend starts a real HTTP server that echoes a distinctive response.
func startHTTPBackend(t *testing.T) *httpBackend {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("backend-ok"))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	return &httpBackend{Server: srv, Addr: ln.Addr().String()}
}

// Helpers

func parseConfigs(t *testing.T, jsonStr string) []*ss.Config {
	t.Helper()
	var cfgs []*ss.Config
	if err := json.Unmarshal([]byte(jsonStr), &cfgs); err != nil {
		t.Fatalf("parse config JSON: %v", err)
	}
	for _, c := range cfgs {
		ss.CheckConfig(c)
	}
	return cfgs
}

func verifyVirtualService(t *testing.T, name, source string) {
	t.Helper()
	for _, s := range ss.ListVirtualServices() {
		if s.Name == name {
			if s.Source != source {
				t.Errorf("%s: expected source '%s', got '%s'", name, source, s.Source)
			}
			return
		}
	}
	t.Errorf("virtual service %s not found in listing", name)
}
