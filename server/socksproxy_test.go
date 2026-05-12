package server

import (
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// TestSocksProxyWithSSProxy_Integration verifies the full socksproxy+ssproxy flow:
// client → SS encrypt → socksproxy+ssproxy → SS backend → echo server.
func TestSocksProxyWithSSProxy_Integration(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	_, echoPort, _ := net.SplitHostPort(echoLn.Addr().String())

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Start a backend SS server that decrypts and forwards to echo.
	backendCfg := &ss.Config{}
	backendCfg.Type = "server"
	backendCfg.Method = "aes-128-gcm"
	backendCfg.Password = "backend-pass"
	ss.CheckConfig(backendCfg)
	defer backendCfg.Close()

	backendLn, err := ss.Listen("127.0.0.1:0", backendCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(conn.(*ss.AcceptedConn))
		}
	}()

	// Start socksproxy+ssproxy with the backend
	ssCfg := &ss.Config{}
	ssCfg.Type = "socksproxy"
	ssCfg.Method = "aes-128-gcm"
	ssCfg.Password = "frontend-pass"
	ssCfg.SSProxy = true
	ssCfg.Backends = []*ss.Config{{
		NetworkConfig: ss.NetworkConfig{Remoteaddr: backendAddr},
		CryptoConfig:  ss.CryptoConfig{Method: "aes-128-gcm", Password: "backend-pass"},
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
			conn, err := socksLn.Accept()
			if err != nil {
				return
			}
			go socksProxyHandler(conn.(*ss.AcceptedConn))
		}
	}()

	// Start local SS client pointing to socksproxy
	cliCfg := &ss.Config{}
	cliCfg.Type = "local"
	cliCfg.Remoteaddr = socksAddr
	cliCfg.Method = "aes-128-gcm"
	cliCfg.Password = "frontend-pass"
	ss.CheckConfig(cliCfg)
	defer cliCfg.Close()

	cliLn, err := ss.Listen("127.0.0.1:0", cliCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SocksAcceptor})
	if err != nil {
		t.Fatal("local client listen:", err)
	}
	defer cliLn.Close()
	localAddr := cliLn.Addr().String()

	go func() {
		for {
			conn, err := cliLn.Accept()
			if err != nil {
				return
			}
			go tcpLocalHandler(conn.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Connect via SOCKS5 + HTTP GET through the whole chain
	conn, err := net.Dial("tcp", localAddr)
	if err != nil {
		t.Fatalf("dial local client: %v", err)
	}
	defer conn.Close()

	host := net.JoinHostPort("127.0.0.1", echoPort)
	request := "GET http://" + host + "/ HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n"
	_, err = conn.Write([]byte(request))
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	var buf [4096]byte
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf[:])
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	response := string(buf[:n])
	if !strings.Contains(response, "HTTP/1.1") {
		t.Errorf("unexpected response: %s", response)
	}
}

// TestSocksProxySSProxy_DirectSSClient verifies a direct SS client
// connecting to socksproxy+ssproxy: SS encrypt → socksproxy decrypt →
// re-encrypt to backend → backend decrypt → echo.
func TestSocksProxySSProxy_DirectSSClient(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	_, echoPort, _ := net.SplitHostPort(echoLn.Addr().String())
	echoAddr := net.JoinHostPort("127.0.0.1", echoPort)

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Backend SS server
	backendCfg := &ss.Config{}
	backendCfg.Type = "server"
	backendCfg.Method = "aes-128-gcm"
	backendCfg.Password = "backend-pass"
	ss.CheckConfig(backendCfg)
	defer backendCfg.Close()

	backendLn, err := ss.Listen("127.0.0.1:0", backendCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(conn.(*ss.AcceptedConn))
		}
	}()

	// Socksproxy with backend
	ssCfg := &ss.Config{}
	ssCfg.Type = "socksproxy"
	ssCfg.Method = "aes-128-gcm"
	ssCfg.Password = "frontend-pass"
	ssCfg.SSProxy = true
	ssCfg.Backends = []*ss.Config{{
		NetworkConfig: ss.NetworkConfig{Remoteaddr: backendAddr},
		CryptoConfig:  ss.CryptoConfig{Method: "aes-128-gcm", Password: "backend-pass"},
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
			conn, err := socksLn.Accept()
			if err != nil {
				return
			}
			go socksProxyHandler(conn.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// SS client → socksproxy (frontend-pass) → backend (backend-pass) → echo
	cliCfg := &ss.Config{}
	cliCfg.Remoteaddr = socksAddr
	cliCfg.Method = "aes-128-gcm"
	cliCfg.Password = "frontend-pass"
	ss.CheckConfig(cliCfg)
	defer cliCfg.Close()

	conn, err := ss.DialSSWithOptions(&ss.DialOptions{
		Target: echoAddr,
		C:      cliCfg,
	})
	if err != nil {
		t.Fatalf("DialSSWithOptions to socksproxy: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello-ssproxy-direct-test")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if string(buf[:n]) != string(payload) {
		t.Errorf("echo mismatch: got %q, want %q", string(buf[:n]), string(payload))
	}
}

// TestSocksProxySSProxy_MultipleSequentialClients verifies the ssproxy
// fallback works for multiple sequential connections.
func TestSocksProxySSProxy_MultipleSequentialClients(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	_, echoPort, _ := net.SplitHostPort(echoLn.Addr().String())
	echoAddr := net.JoinHostPort("127.0.0.1", echoPort)

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	backendCfg := &ss.Config{}
	backendCfg.Type = "server"
	backendCfg.Method = "aes-128-gcm"
	backendCfg.Password = "backend-pass"
	ss.CheckConfig(backendCfg)
	defer backendCfg.Close()

	backendLn, err := ss.Listen("127.0.0.1:0", backendCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(conn.(*ss.AcceptedConn))
		}
	}()

	ssCfg := &ss.Config{}
	ssCfg.Type = "socksproxy"
	ssCfg.Method = "aes-128-gcm"
	ssCfg.Password = "frontend-pass"
	ssCfg.SSProxy = true
	ssCfg.Backends = []*ss.Config{{
		NetworkConfig: ss.NetworkConfig{Remoteaddr: backendAddr},
		CryptoConfig:  ss.CryptoConfig{Method: "aes-128-gcm", Password: "backend-pass"},
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
			conn, err := socksLn.Accept()
			if err != nil {
				return
			}
			go socksProxyHandler(conn.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	for i := range 10 {
		cliCfg := &ss.Config{}
		cliCfg.Remoteaddr = socksAddr
		cliCfg.Method = "aes-128-gcm"
		cliCfg.Password = "frontend-pass"
		ss.CheckConfig(cliCfg)

		conn, err := ss.DialSSWithOptions(&ss.DialOptions{
			Target: echoAddr,
			C:      cliCfg,
		})
		if err != nil {
			t.Fatalf("client %d: DialSSWithOptions: %v", i, err)
		}

		payload := fmt.Sprintf("hello-ssproxy-%d", i)
		if _, err := conn.Write([]byte(payload)); err != nil {
			conn.Close()
			cliCfg.Close()
			t.Fatalf("client %d: write: %v", i, err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			conn.Close()
			cliCfg.Close()
			t.Fatalf("client %d: read: %v", i, err)
		}

		if string(buf[:n]) != payload {
			t.Errorf("client %d: echo mismatch: got %q, want %q", i, string(buf[:n]), payload)
		}

		conn.Close()
		cliCfg.Close()
	}
}

// TestSocksProxy_SOCKS5Only verifies socksproxy works as a plain SOCKS5
// proxy (no ssproxy fallback). A SOCKS5 client connects, socksproxy
// reads the request and forwards through the backend.
func TestSocksProxy_SOCKS5Only(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	echoAddr := echoLn.Addr().String()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	// Backend SS server
	backendCfg := &ss.Config{}
	backendCfg.Type = "server"
	backendCfg.Method = "aes-128-gcm"
	backendCfg.Password = "backend-pass"
	ss.CheckConfig(backendCfg)
	defer backendCfg.Close()

	backendLn, err := ss.Listen("127.0.0.1:0", backendCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SSHandler})
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	defer backendLn.Close()
	backendAddr := backendLn.Addr().String()

	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go tcpRemoteHandler(conn.(*ss.AcceptedConn))
		}
	}()

	// Socksproxy WITHOUT ssproxy
	ssCfg := &ss.Config{}
	ssCfg.Type = "socksproxy"
	ssCfg.Backends = []*ss.Config{{
		NetworkConfig: ss.NetworkConfig{Remoteaddr: backendAddr},
		CryptoConfig:  ss.CryptoConfig{Method: "aes-128-gcm", Password: "backend-pass"},
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
			conn, err := socksLn.Accept()
			if err != nil {
				return
			}
			go socksProxyHandler(conn.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// Connect via plain SOCKS5
	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial socksproxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting
	conn.Write([]byte{0x05, 0x01, 0x00})
	greetingResp := make([]byte, 2)
	io.ReadFull(conn, greetingResp)
	if greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
		t.Fatalf("socks5 greeting rejected: %x", greetingResp)
	}

	// SOCKS5 CONNECT request to echo using domain name
	host, portStr, _ := net.SplitHostPort(echoAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, net.ParseIP(host).To4()...)
	req = append(req, byte(port>>8), byte(port&0xff))
	conn.Write(req)

	reqResp := make([]byte, 10)
	io.ReadFull(conn, reqResp)
	if reqResp[1] != 0x00 {
		t.Fatalf("socks5 request rejected: 0x%02x", reqResp[1])
	}

	payload := "hello-socks5-only"
	conn.Write([]byte(payload))

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Errorf("echo mismatch: got %q, want %q", string(buf[:n]), payload)
	}
}
