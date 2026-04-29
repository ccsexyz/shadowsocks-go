package server

import (
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"github.com/xtaci/smux"
)

func echoServer(t *testing.T) (string, string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return ln.Addr().String(), host, port
}

func socks5Connect(t *testing.T, conn net.Conn, host string, port int) {
	t.Helper()
	conn.Write([]byte{5, 1, 0})
	buf := make([]byte, 512)
	io.ReadFull(conn, buf[:2])

	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))
	conn.Write(req)
	io.ReadFull(conn, buf[:10])
	if buf[1] != 0 {
		t.Fatalf("SOCKS5 CONNECT failed: %x", buf[:2])
	}
}

func TestVirtualPipeline(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	srv := &ss.Config{}
	srv.Type = "server"
	srv.Localaddr = "@vpipe-srv"
	srv.Method = "aes-256-gcm"
	srv.Password = "test"
	ss.CheckConfig(srv)
	defer srv.Close()
	go RunTCPRemoteServer(srv)

	cli := &ss.Config{}
	cli.Type = "local"
	cli.Localaddr = "@vpipe-cli"
	cli.Remoteaddr = "@vpipe-srv"
	cli.Method = "aes-256-gcm"
	cli.Password = "test"
	ss.CheckConfig(cli)
	defer cli.Close()
	go RunTCPLocalServer(cli)

	time.Sleep(200 * time.Millisecond)

	client, err := ss.DialVirtual("@vpipe-cli")
	if err != nil {
		t.Fatalf("DialVirtual: %v", err)
	}
	defer client.Close()

	socks5Connect(t, client, echoHost, echoPort)

	payload := "hello-pipeline"
	client.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(client, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}
}

func TestVirtualMultiplePipelines(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	const numPipes = 3
	var cfgs []*ss.Config

	for i := range numPipes {
		srvName := "@mp-srv-" + strconv.Itoa(i)
		cliName := "@mp-cli-" + strconv.Itoa(i)

		srv := &ss.Config{}
		srv.Type = "server"
		srv.Localaddr = srvName
		srv.Method = "aes-256-gcm"
		srv.Password = "test-" + strconv.Itoa(i)
		ss.CheckConfig(srv)
		go RunTCPRemoteServer(srv)

		cli := &ss.Config{}
		cli.Type = "local"
		cli.Localaddr = cliName
		cli.Remoteaddr = srvName
		cli.Method = "aes-256-gcm"
		cli.Password = "test-" + strconv.Itoa(i)
		ss.CheckConfig(cli)
		go RunTCPLocalServer(cli)

		cfgs = append(cfgs, srv, cli)
	}
	defer func() {
		for _, c := range cfgs {
			c.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)

	var wg sync.WaitGroup
	for i := range numPipes {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cliName := "@mp-cli-" + strconv.Itoa(id)

			client, err := ss.DialVirtual(cliName)
			if err != nil {
				t.Errorf("pipe %d: DialVirtual: %v", id, err)
				return
			}
			defer client.Close()

			socks5Connect(t, client, echoHost, echoPort)

			payload := []byte("pipe-" + strconv.Itoa(id) + "-data")
			client.Write(payload)
			resp := make([]byte, len(payload))
			io.ReadFull(client, resp)
			if string(resp) != string(payload) {
				t.Errorf("pipe %d: expected '%s', got '%s'", id, payload, string(resp))
			}
		}(i)
	}
	wg.Wait()
}

func TestRtunnelVirtualService(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	// --- Server side: rtunnel server with virtual service ---
	srv := &ss.Config{}
	srv.Type = "rtunnelserver"
	srv.Method = "aes-256-gcm"
	srv.Password = "test"
	srv.RtunnelService = "@rtun-svc"
	ss.CheckConfig(srv)
	defer srv.Close()

	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(srv.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}

	ln, err := ss.Listen("127.0.0.1:0", srv, handlers)
	if err != nil {
		t.Fatal("server listen:", err)
	}
	defer ln.Close()
	serverAddr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go rtunnelServerHandler(conn.(*ss.AcceptedConn))
		}
	}()

	// --- Client side: rtunnel client ---
	cli := &ss.Config{}
	cli.Type = "rtunnelclient"
	cli.Remoteaddr = net.JoinHostPort(echoHost, strconv.Itoa(echoPort))
	cli.Backend = &ss.Config{}
	cli.Backend.Remoteaddr = serverAddr
	cli.Backend.Method = "aes-256-gcm"
	cli.Backend.Password = "test"
	ss.CheckConfig(cli)
	defer cli.Close()
	go RunRtunnelClient(cli)

	// Non-2022 SS defers header sending via RemainConn.wremain — the first
	// smux keepalive (1s interval) triggers the flush. Give it enough time.
	time.Sleep(2 * time.Second)

	// Verify virtual service is listed
	found := false
	for _, s := range ss.ListVirtualServices() {
		if s.Name == "@rtun-svc" {
			found = true
			break
		}
	}
	if !found {
		t.Error("@rtun-svc should appear in ListVirtualServices")
	}

	// Dial the virtual service and do an echo test
	conn, err := ss.DialVirtual("@rtun-svc")
	if err != nil {
		t.Fatalf("DialVirtual @rtun-svc: %v", err)
	}
	defer conn.Close()

	payload := "hello-rtunnel-virt"
	conn.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(conn, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}
}

func TestRtunnelVirtualService2022(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	srv := &ss.Config{}
	srv.Type = "rtunnelserver"
	srv.Method = "2022-blake3-aes-256-gcm"
	srv.Password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	srv.RtunnelService = "@rtun2022-svc"
	ss.CheckConfig(srv)
	defer srv.Close()

	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(srv.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}

	ln, err := ss.Listen("127.0.0.1:0", srv, handlers)
	if err != nil {
		t.Fatal("server listen:", err)
	}
	defer ln.Close()
	serverAddr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go rtunnelServerHandler(conn.(*ss.AcceptedConn))
		}
	}()

	cli := &ss.Config{}
	cli.Type = "rtunnelclient"
	cli.Remoteaddr = net.JoinHostPort(echoHost, strconv.Itoa(echoPort))
	cli.Backend = &ss.Config{}
	cli.Backend.Remoteaddr = serverAddr
	cli.Backend.Method = "2022-blake3-aes-256-gcm"
	cli.Backend.Password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	ss.CheckConfig(cli)
	defer cli.Close()
	go RunRtunnelClient(cli)

	time.Sleep(300 * time.Millisecond)

	conn, err := ss.DialVirtual("@rtun2022-svc")
	if err != nil {
		t.Fatalf("DialVirtual @rtun2022-svc: %v", err)
	}
	defer conn.Close()

	payload := "hello-rtunnel-2022"
	conn.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(conn, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}
}

func TestRtunnelVirtualServiceMultipleConnections(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	srv := &ss.Config{}
	srv.Type = "rtunnelserver"
	srv.Method = "aes-256-gcm"
	srv.Password = "test"
	srv.RtunnelService = "@rtun-multi-svc"
	ss.CheckConfig(srv)
	defer srv.Close()

	handlers := []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler}

	ln, err := ss.Listen("127.0.0.1:0", srv, handlers)
	if err != nil {
		t.Fatal("server listen:", err)
	}
	defer ln.Close()
	serverAddr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go rtunnelServerHandler(conn.(*ss.AcceptedConn))
		}
	}()

	cli := &ss.Config{}
	cli.Type = "rtunnelclient"
	cli.Remoteaddr = net.JoinHostPort(echoHost, strconv.Itoa(echoPort))
	cli.Backend = &ss.Config{}
	cli.Backend.Remoteaddr = serverAddr
	cli.Backend.Method = "aes-256-gcm"
	cli.Backend.Password = "test"
	ss.CheckConfig(cli)
	defer cli.Close()
	go RunRtunnelClient(cli)

	time.Sleep(2 * time.Second)

	const numConns = 5
	var wg sync.WaitGroup

	for i := range numConns {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := ss.DialVirtual("@rtun-multi-svc")
			if err != nil {
				t.Errorf("conn %d: DialVirtual: %v", id, err)
				return
			}
			defer conn.Close()

			payload := []byte("rtun-echo-" + strconv.Itoa(id))
			conn.Write(payload)
			resp := make([]byte, len(payload))
			io.ReadFull(conn, resp)
			if string(resp) != string(payload) {
				t.Errorf("conn %d: expected '%s', got '%s'", id, payload, string(resp))
			}
		}(i)
	}

	wg.Wait()

	// Verify accept count
	for _, s := range ss.ListVirtualServices() {
		if s.Name == "@rtun-multi-svc" {
			if s.AcceptCount < int64(numConns) {
				t.Errorf("expected AcceptCount >= %d, got %d", numConns, s.AcceptCount)
			}
			break
		}
	}
}

func TestVirtualServiceAsSSProxyTarget(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	// A plain SS server listening on a virtual address
	remote := &ss.Config{}
	remote.Type = "server"
	remote.Localaddr = "@proxy-remote"
	remote.Method = "aes-256-gcm"
	remote.Password = "test"
	ss.CheckConfig(remote)
	defer remote.Close()
	go RunTCPRemoteServer(remote)

	// An ssproxy server that decrypts SS traffic and re-encrypts to the virtual server.
	// This tests that DialSSWithOptions (used inside ssproxyHandler) can resolve
	// @-prefixed addresses for the backend/next-hop.
	proxy := &ss.Config{}
	proxy.Type = "ssproxy"
	proxy.Method = "aes-256-gcm"
	proxy.Password = "test"
	proxy.Backend = &ss.Config{}
	proxy.Backend.Remoteaddr = "@proxy-remote"
	proxy.Backend.Method = "aes-256-gcm"
	proxy.Backend.Password = "test"
	ss.CheckConfig(proxy)
	defer proxy.Close()

	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(proxy.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}

	ln, err := ss.Listen("127.0.0.1:0", proxy, handlers)
	if err != nil {
		t.Fatal("proxy listen:", err)
	}
	defer ln.Close()
	proxyAddr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go ssproxyHandler(conn.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Connect through the ssproxy as an SS client, targeting the echo server.
	// Flow: client -> SS encrypt -> ssproxy -> SS decrypt -> re-encrypt to @proxy-remote -> virtual server decrypt -> echo
	client := &ss.Config{}
	client.Method = "aes-256-gcm"
	client.Password = "test"
	client.Remoteaddr = proxyAddr
	client.Type = "local"
	ss.CheckConfig(client)
	defer client.Close()

	rconn, err := ss.DialSSWithOptions(&ss.DialOptions{
		Target: net.JoinHostPort(echoHost, strconv.Itoa(echoPort)),
		C:      client,
	})
	if err != nil {
		t.Fatalf("DialSSWithOptions: %v", err)
	}
	defer rconn.Close()

	payload := "through-ssproxy-virt"
	rconn.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(rconn, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}
}

func TestVirtualServiceWithSmuxDirect(t *testing.T) {
	// Test virtual service + smux without the rtunnel layer:
	// Register a virtual service that, when dialed, opens a smux stream
	// over an existing SS connection. This verifies the core mechanism
	// used by rtunnel.

	_, echoHost, echoPort := echoServer(t)

	// Set up a real TCP SS server
	srv := &ss.Config{}
	srv.Type = "server"
	srv.Localaddr = "127.0.0.1:0"
	srv.Method = "aes-256-gcm"
	srv.Password = "test"
	ss.CheckConfig(srv)
	defer srv.Close()

	serverLn, err := ss.Listen(srv.Localaddr, srv, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal(err)
	}
	defer serverLn.Close()
	serverAddr := serverLn.Addr().String()

	// Accept one SS connection, create smux server over it,
	// then expose a virtual service that opens smux streams.
	type ready struct{}
	readyCh := make(chan ready)
	go func() {
		conn, err := serverLn.Accept()
		if err != nil {
			return
		}
		ac := conn.(*ss.AcceptedConn)
		defer ac.Conn.Close()

		session, err := smux.Server(ac.Conn, smux.DefaultConfig())
		if err != nil {
			t.Error("smux server:", err)
			return
		}
		defer session.Close()

		// Register a virtual service backed by this smux session
		vln, err := ss.RegisterVirtual("@smux-direct", "test-smux")
		if err != nil {
			t.Error("RegisterVirtual:", err)
			return
		}
		defer ss.UnregisterVirtual("@smux-direct")

		close(readyCh)

		for {
			vconn, err := vln.Accept()
			if err != nil {
				return
			}
			stream, err := session.OpenStream()
			if err != nil {
				vconn.Close()
				return
			}
			go func(s *smux.Stream, c net.Conn) {
				defer s.Close()
				defer c.Close()
				ss.Pipe(c, s, ac.Config)
			}(stream, vconn)
		}
	}()

	// Client: dial the SS server, create smux client, then proxy streams to echo
	go func() {
		cliCfg := &ss.Config{}
		cliCfg.Method = "aes-256-gcm"
		cliCfg.Password = "test"
		cliCfg.Remoteaddr = serverAddr
		ss.CheckConfig(cliCfg)

		rconn, err := ss.DialSSWithOptions(&ss.DialOptions{
			Target: serverAddr,
			C:      cliCfg,
		})
		if err != nil {
			t.Error("DialSSWithOptions:", err)
			return
		}
		defer rconn.Close()

		smuxCfg := smux.DefaultConfig()
		smuxCfg.KeepAliveInterval = time.Second // must fire within the 4s SS read deadline
		session, err := smux.Client(rconn, smuxCfg)
		if err != nil {
			t.Error("smux client:", err)
			return
		}
		defer session.Close()

		for {
			stream, err := session.AcceptStream()
			if err != nil {
				return
			}
			go func(s *smux.Stream) {
				defer s.Close()
				target := net.JoinHostPort(echoHost, strconv.Itoa(echoPort))
				tconn, err := ss.DialTCP(target, srv)
				if err != nil {
					return
				}
				defer tconn.Close()
				ss.Pipe(s, tconn, srv)
			}(stream)
		}
	}()

	// Wait for virtual service to be ready
	<-readyCh
	time.Sleep(2 * time.Second)

	// Dial the virtual service
	vconn, err := ss.DialVirtual("@smux-direct")
	if err != nil {
		t.Fatalf("DialVirtual: %v", err)
	}
	defer vconn.Close()

	payload := "hello-smux-virt"
	vconn.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(vconn, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}
}

func TestVirtualServiceChaining(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	hop2 := &ss.Config{}
	hop2.Type = "server"
	hop2.Localaddr = "@chain-hop2"
	hop2.Method = "aes-256-gcm"
	hop2.Password = "hop2"
	ss.CheckConfig(hop2)
	defer hop2.Close()
	go RunTCPRemoteServer(hop2)

	hop1 := &ss.Config{}
	hop1.Type = "local"
	hop1.Localaddr = "@chain-hop1"
	hop1.Remoteaddr = "@chain-hop2"
	hop1.Method = "aes-256-gcm"
	hop1.Password = "hop2"
	ss.CheckConfig(hop1)
	defer hop1.Close()
	go RunTCPLocalServer(hop1)

	time.Sleep(200 * time.Millisecond)

	client, err := ss.DialVirtual("@chain-hop1")
	if err != nil {
		t.Fatalf("DialVirtual: %v", err)
	}
	defer client.Close()

	socks5Connect(t, client, echoHost, echoPort)

	payload := "through-two-hops"
	client.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(client, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}
}
