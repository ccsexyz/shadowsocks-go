package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// TestSocksProxyWithSSProxy_Integration verifies the full socksproxy+ssproxy flow:
// client → SS encrypt → socksproxy+ssproxy → SS backend → echo server.
func TestSocksProxyWithSSProxy_Integration(t *testing.T) {
	socksAddr, echoAddr := startSocksProxyChain(t, "aes-128-gcm", "backend-pass", "aes-128-gcm", "frontend-pass")
	_, echoPort, _ := net.SplitHostPort(echoAddr)

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
	socksAddr, echoAddr := startSocksProxyChain(t, "aes-128-gcm", "backend-pass", "aes-128-gcm", "frontend-pass")

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
	n, err := ss.ReadN(conn, buf, nil)
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
	socksAddr, echoAddr := startSocksProxyChain(t, "aes-128-gcm", "backend-pass", "aes-128-gcm", "frontend-pass")

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
		n, err := ss.ReadN(conn, buf, nil)
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
	socksAddr, echoAddr := startSocksProxyChain(t, "aes-128-gcm", "backend-pass", "", "")

	// Connect via plain SOCKS5
	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatalf("dial socksproxy: %v", err)
	}
	defer conn.Close()

	if err := socks5Handshake(conn, echoAddr); err != nil {
		t.Fatal("socks5 handshake:", err)
	}

	payload := "hello-socks5-only"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}

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

// TestSocksProxy2022MultiPacket drives the 2022 crypto path in socksproxy.
// Each pkt is a separate write→echo cycle: the first is bundled into the 2022
// request header, the rest flow through the Pipe — this catches bugs where
// the initial data is double-written after the header already included it.

func socks5Handshake(conn net.Conn, target string) error {
	// SOCKS5 greeting
	conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("unexpected greeting response: %x", resp)
	}

	// SOCKS5 connect request
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("only IPv4 targets supported in test")
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)

	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip.To4()...)
	req = append(req, byte(port>>8), byte(port))
	conn.Write(req)

	resp2 := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp2); err != nil {
		return err
	}
	if resp2[0] != 0x05 || resp2[1] != 0x00 {
		return fmt.Errorf("SOCKS5 connect failed: %x", resp2[:2])
	}
	return nil
}

func TestSocksProxy2022MultiPacket(t *testing.T) {
	psk := "AAAAAAAAAAAAAAAAAAAAAA=="
	method := "2022-blake3-aes-128-gcm"
	socksAddr, echoAddr := startSocksProxyChain(t, method, psk, method, psk)

	// SOCKS5 client sends 5 pkt packets sequentially and verifies echo.
	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal("dial socksproxy:", err)
	}
	defer conn.Close()

	if err := socks5Handshake(conn, echoAddr); err != nil {
		t.Fatal("SOCKS5 handshake:", err)
	}

	for i := 0; i < 5; i++ {
		payload := fmt.Sprintf("pkt-%d-%s", i, strings.Repeat("x", 32))
		pkt := append([]byte{0, 0, 0, byte(len(payload))}, []byte(payload)...)
		if _, err := conn.Write(pkt); err != nil {
			t.Fatalf("write pkt %d: %v", i, err)
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		echo := make([]byte, len(pkt))
		if _, err := io.ReadFull(conn, echo); err != nil {
			t.Fatalf("read echo pkt %d: %v", i, err)
		}
		if !bytes.Equal(echo, pkt) {
			t.Fatalf("pkt %d echo mismatch", i)
		}
	}
}

// startSocksProxyChain boots the shared socksproxy rig: an echo target, an SS
// backend server behind it, and a socksproxy listener over the backend. A
// 2022 backendMethod selects SS2022Handler, anything else SSHandler. Non-empty
// proxyMethod/proxyPassword enable the ssproxy re-encrypt path; empty values
// keep the proxy a plain SOCKS5 pass-through. Returns (socksproxyAddr, echoAddr).
func startSocksProxyChain(t *testing.T, backendMethod, backendPassword, proxyMethod, proxyPassword string) (string, string) {
	t.Helper()
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echoLn.Close() })
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
	backendCfg.Method = backendMethod
	backendCfg.Password = backendPassword
	ss.CheckConfig(backendCfg)
	backendHandler := ss.SSHandler
	if strings.HasPrefix(backendMethod, "2022-") {
		backendHandler = ss.SS2022Handler
	}
	backendLn, err := ss.Listen("127.0.0.1:0", backendCfg, []ss.AcceptHandler{ss.LimitHandler, backendHandler})
	if err != nil {
		t.Fatal("backend listen:", err)
	}
	t.Cleanup(func() { backendLn.Close() })
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
	if proxyMethod != "" {
		ssCfg.SSProxy = true
		ssCfg.Method = proxyMethod
		ssCfg.Password = proxyPassword
	}
	ssCfg.Backends = []*ss.Config{{
		NetworkConfig: ss.NetworkConfig{Remoteaddr: backendLn.Addr().String()},
		CryptoConfig:  ss.CryptoConfig{Method: backendMethod, Password: backendPassword},
	}}
	ss.CheckConfig(ssCfg)
	t.Cleanup(func() { ssCfg.Close() })

	socksLn, err := ss.Listen("127.0.0.1:0", ssCfg, []ss.AcceptHandler{ss.LimitHandler, ss.SocksAcceptor})
	if err != nil {
		t.Fatal("socksproxy listen:", err)
	}
	t.Cleanup(func() { socksLn.Close() })
	go func() {
		for {
			conn, err := socksLn.Accept()
			if err != nil {
				return
			}
			go socksProxyHandler(conn.(*ss.AcceptedConn))
		}
	}()
	return socksLn.Addr().String(), echoLn.Addr().String()
}

// startSocks466EchoProxy is the classic-backend plain-SOCKS5 rig used by the
// SOCKS protocol tests.
func startSocks466EchoProxy(t *testing.T) (string, string) {
	t.Helper()
	return startSocksProxyChain(t, "aes-128-gcm", "backend-pass", "", "")
}

// echoOnce dials the socksproxy, performs the pre-built handshake bytes,
// sends payload, and requires the echo to be EXACTLY the payload. Any
// protocol-framing bytes replayed into the tunnel fail the test.
func echoExact(t *testing.T, addr string, handshake []byte, payload string, expectReply int) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(handshake); err != nil {
		t.Fatal(err)
	}
	if expectReply > 0 {
		reply := make([]byte, expectReply)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("handshake reply: %v", err)
		}
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload)+64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf[:n]) != payload {
		t.Fatalf("tunnel stream corrupted: got %q, want %q", buf[:n], payload)
	}
	// Nothing else may arrive: protocol bytes replayed into the tunnel
	// would come back as a spurious echo here.
	conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if n, err := conn.Read(buf); err == nil && n > 0 {
		t.Fatalf("unexpected trailing bytes in tunnel: %q", buf[:n])
	}
}

// TestSocks4NoRequestReplay pins that SOCKS4 request bytes are not replayed
// into the tunneled stream.
func TestSocks4NoRequestReplay(t *testing.T) {
	socksAddr, echoAddr := startSocks466EchoProxy(t)
	_, portStr, _ := net.SplitHostPort(echoAddr)
	payload := "socks4-payload-check"

	// SOCKS4 CONNECT to the echo server via its loopback IP.
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x04, 0x01}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	req = append(req, portBytes[:]...)
	req = append(req, 127, 0, 0, 1)
	req = append(req, []byte("user")...)
	req = append(req, 0)
	echoExact(t, socksAddr, req, payload, 8)
}

// TestSocks4aNoRequestReplay covers the socks4a (domain) variant.
func TestSocks4aNoRequestReplay(t *testing.T) {
	socksAddr, echoAddr := startSocks466EchoProxy(t)
	_, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.Atoi(portStr)
	payload := "socks4a-payload-check"

	req := []byte{0x04, 0x01}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	req = append(req, portBytes[:]...)
	req = append(req, 0, 0, 0, 1) // socks4a: dummy IP signals domain mode
	req = append(req, []byte("user")...)
	req = append(req, 0)
	req = append(req, []byte("localhost")...)
	req = append(req, 0)
	echoExact(t, socksAddr, req, payload, 8)
}

// TestSocks6NoRequestReplay pins the double-RemainConn-wrapping case: a
// payload followed by the whole request must not replay into the tunnel.
func TestSocks6NoRequestReplay(t *testing.T) {
	socksAddr, echoAddr := startSocks466EchoProxy(t)
	_, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.Atoi(portStr)
	payload := "socks6-payload-check"

	req := []byte{0x06, 0x01, 0x01} // VER CMD ATYP=IPv4
	req = append(req, 127, 0, 0, 1)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	req = append(req, portBytes[:]...)
	// SOCKS6 sends no handshake reply; the tunnel starts immediately.
	echoExact(t, socksAddr, req, payload, 0)
}

// TestSocks5PipelinedGreetingAndRequest covers greeting + CONNECT arriving in
// a single TCP segment: the overlong greeting must be accepted.
func TestSocks5PipelinedGreetingAndRequest(t *testing.T) {
	socksAddr, echoAddr := startSocks466EchoProxy(t)
	_, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.Atoi(portStr)
	payload := "socks5-pipelined-check"

	handshake := []byte{0x05, 0x01, 0x00} // greeting: VER, 1 method, no-auth
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, 127, 0, 0, 1)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	req = append(req, portBytes[:]...)
	handshake = append(handshake, req...)
	echoExact(t, socksAddr, handshake, payload, 12)
}

// TestSocks5RejectsUserPassOnlyClient pins the RFC 1928 method negotiation:
// a client offering only user/pass must get 0xFF (no acceptable methods),
// not a {5,0} success it never offered.
func TestSocks5RejectsUserPassOnlyClient(t *testing.T) {
	socksAddr, _ := startSocks466EchoProxy(t)
	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read method reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0xFF {
		t.Fatalf("method reply = %x, want 05 ff", reply)
	}
}

// TestSocks5RequestPayloadSameSegment pins the leftover-replay rule: a client
// that sends greeting + CONNECT request + payload in a single TCP segment
// must observe its payload echoed exactly — the bytes past the request inside
// the same peek belong to the tunnel, not the parser.
func TestSocks5RequestPayloadSameSegment(t *testing.T) {
	socksAddr, echoAddr := startSocks466EchoProxy(t)
	_, portStr, _ := net.SplitHostPort(echoAddr)
	port, _ := strconv.Atoi(portStr)
	payload := "socks5-same-segment-payload"

	buf := make([]byte, 0, 128)
	buf = append(buf, 0x05, 0x01, 0x00) // greeting: VER, 1 method, no-auth
	req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	req = append(req, portBytes[:]...)
	buf = append(buf, req...)
	buf = append(buf, payload...)

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(buf); err != nil {
		t.Fatal(err)
	}
	// 2-byte method reply + 10-byte CONNECT reply.
	reply := make([]byte, 12)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("handshake reply: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("tunnel stream corrupted: got %q, want %q", got, payload)
	}
}

// TestHTTPConnectPipelinedPayload pins the CONNECT excess rule: bytes that
// follow the CONNECT header inside the same segment belong to the tunneled
// stream and must reach the target.
func TestHTTPConnectPipelinedPayload(t *testing.T) {
	socksAddr, echoAddr := startSocks466EchoProxy(t)
	payload := "http-connect-pipelined-payload"

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "CONNECT " + echoAddr + " HTTP/1.1\r\nHost: " + echoAddr + "\r\n\r\n" + payload
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 0, 128)
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, one); err != nil {
			t.Fatalf("read connect reply: %v", err)
		}
		reply = append(reply, one[0])
		if bytes.HasSuffix(reply, []byte("\r\n\r\n")) {
			break
		}
		if len(reply) > 128 {
			t.Fatalf("runaway connect reply: %q", reply)
		}
	}
	if !bytes.HasPrefix(reply, []byte("HTTP/1.1 200")) {
		t.Fatalf("connect reply = %q", reply)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("tunnel stream corrupted: got %q, want %q", got, payload)
	}
}

// TestHTTPConnectPipelinedPayloadLargeSegment pins the stream-order rule for
// pipelined data: the header parse buffer is 4KB while the peeked segment is
// 64KB, so a large same-segment payload is split between the parser's excess
// and the peeked conn's remain — both must reach the tunnel, excess first.
// With the parts out of order the echo comes back scrambled.
func TestHTTPConnectPipelinedPayloadLargeSegment(t *testing.T) {
	socksAddr, echoAddr := startSocks466EchoProxy(t)
	payload := make([]byte, 5000)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	conn, err := net.Dial("tcp", socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := "CONNECT " + echoAddr + " HTTP/1.1\r\nHost: " + echoAddr + "\r\n\r\n"
	if _, err := conn.Write(append([]byte(req), payload...)); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 0, 128)
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, one); err != nil {
			t.Fatalf("read connect reply: %v", err)
		}
		reply = append(reply, one[0])
		if bytes.HasSuffix(reply, []byte("\r\n\r\n")) {
			break
		}
		if len(reply) > 128 {
			t.Fatalf("runaway connect reply: %q", reply)
		}
	}
	if !bytes.HasPrefix(reply, []byte("HTTP/1.1 200")) {
		t.Fatalf("connect reply = %q", reply)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("tunnel stream corrupted across the excess/remain split")
	}
}
