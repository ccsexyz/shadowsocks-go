package server

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// serveMinimalSOCKS5 is a minimal SOCKS5 proxy that handles CONNECT to IPv4.
func serveMinimalSOCKS5(ln net.Listener, target string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(conn net.Conn) {
			defer conn.Close()

			buf := make([]byte, 256)

			// Read greeting: VER, NMETHODS, METHODS...
			if _, err := io.ReadFull(conn, buf[:2]); err != nil {
				return
			}
			if buf[0] != 0x05 {
				return
			}
			nmethods := int(buf[1])
			if nmethods > 0 {
				if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
					return
				}
			}
			// Respond: no auth
			conn.Write([]byte{0x05, 0x00})

			// Read request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
			if _, err := io.ReadFull(conn, buf[:4]); err != nil {
				return
			}
			if buf[0] != 0x05 || buf[1] != 0x01 { // CONNECT only
				return
			}
			atyp := buf[3]
			var host string
			switch atyp {
			case 0x01: // IPv4
				if _, err := io.ReadFull(conn, buf[:4]); err != nil {
					return
				}
				host = net.IP(buf[:4]).String()
			case 0x03: // Domain
				if _, err := io.ReadFull(conn, buf[:1]); err != nil {
					return
				}
				domainLen := int(buf[0])
				if _, err := io.ReadFull(conn, buf[:domainLen]); err != nil {
					return
				}
				host = string(buf[:domainLen])
			default:
				return
			}
			if _, err := io.ReadFull(conn, buf[:2]); err != nil {
				return
			}
			port := int(buf[0])<<8 | int(buf[1])

			// Connect to actual target
			dest := net.JoinHostPort(host, strconv.Itoa(port))
			remote, err := net.Dial("tcp", dest)
			if err != nil {
				conn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}
			defer remote.Close()

			// Respond success
			conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

			// Bidirectional copy
			done := make(chan struct{}, 2)
			go func() {
				io.Copy(remote, conn)
				done <- struct{}{}
			}()
			go func() {
				io.Copy(conn, remote)
				done <- struct{}{}
			}()
			<-done
		}(c)
	}
}

// TestSSProxy_ForwardToSOCKS5 verifies that ssproxy can decrypt an incoming
// SS connection and forward the plain traffic to a SOCKS5 proxy server.
//
//	SS client → ssproxy (decrypt) → SOCKS5 proxy → echo server
func TestSSProxy_ForwardToSOCKS5(t *testing.T) {
	// 1. Echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	_, echoPort, _ := net.SplitHostPort(echoLn.Addr().String())
	echoAddr := "127.0.0.1:" + echoPort

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

	// 2. Minimal SOCKS5 proxy → echo server
	socks5Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks5Ln.Close()
	socks5Addr := socks5Ln.Addr().String()
	go serveMinimalSOCKS5(socks5Ln, echoAddr)

	// 3. ssproxy with backend method=socks5
	ssCfg := &ss.Config{}
	ssCfg.Type = "ssproxy"
	ssCfg.Method = "aes-128-gcm"
	ssCfg.Password = "frontend-pass"
	ssCfg.Backends = []*ss.Config{{
		NetworkConfig: ss.NetworkConfig{Remoteaddr: socks5Addr},
		CryptoConfig:  ss.CryptoConfig{Method: "socks5"},
	}}
	ss.CheckConfig(ssCfg)
	defer ssCfg.Close()

	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(ssCfg.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}

	ssLn, err := ss.Listen("127.0.0.1:0", ssCfg, handlers)
	if err != nil {
		t.Fatal("ssproxy listen:", err)
	}
	defer ssLn.Close()
	ssAddr := ssLn.Addr().String()

	go func() {
		for {
			conn, err := ssLn.Accept()
			if err != nil {
				return
			}
			go ssproxyHandler(conn.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	// 4. SS client → ssproxy (frontend-pass) → SOCKS5 → echo
	cliCfg := &ss.Config{}
	cliCfg.Remoteaddr = ssAddr
	cliCfg.Method = "aes-128-gcm"
	cliCfg.Password = "frontend-pass"
	ss.CheckConfig(cliCfg)
	defer cliCfg.Close()

	conn, err := ss.DialSSWithOptions(&ss.DialOptions{
		Target: echoAddr,
		C:      cliCfg,
	})
	if err != nil {
		t.Fatalf("DialSSWithOptions to ssproxy: %v", err)
	}
	defer conn.Close()

	payload := "hello-ssproxy-to-socks5"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	n, err := ss.ReadN(conn, buf, nil)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	got := string(buf[:n])
	if got != payload {
		t.Errorf("echo mismatch:\n  want: %q\n  got:  %q", payload, got)
	} else {
		t.Logf("echo OK: %q", got)
	}
}

// TestSSProxy_ForwardToSOCKS5_MultipleConnections verifies multiple
// sequential connections all succeed through ssproxy→SOCKS5.
func TestSSProxy_ForwardToSOCKS5_MultipleConnections(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	_, echoPort, _ := net.SplitHostPort(echoLn.Addr().String())
	echoAddr := "127.0.0.1:" + echoPort

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

	socks5Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socks5Ln.Close()
	socks5Addr := socks5Ln.Addr().String()
	go serveMinimalSOCKS5(socks5Ln, echoAddr)

	ssCfg := &ss.Config{}
	ssCfg.Type = "ssproxy"
	ssCfg.Method = "aes-128-gcm"
	ssCfg.Password = "frontend-pass"
	ssCfg.Backends = []*ss.Config{{
		NetworkConfig: ss.NetworkConfig{Remoteaddr: socks5Addr},
		CryptoConfig:  ss.CryptoConfig{Method: "socks5"},
	}}
	ss.CheckConfig(ssCfg)
	defer ssCfg.Close()

	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(ssCfg.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}

	ssLn, err := ss.Listen("127.0.0.1:0", ssCfg, handlers)
	if err != nil {
		t.Fatal("ssproxy listen:", err)
	}
	defer ssLn.Close()
	ssAddr := ssLn.Addr().String()

	go func() {
		for {
			conn, err := ssLn.Accept()
			if err != nil {
				return
			}
			go ssproxyHandler(conn.(*ss.AcceptedConn))
		}
	}()

	time.Sleep(200 * time.Millisecond)

	for i := range 5 {
		cliCfg := &ss.Config{}
		cliCfg.Remoteaddr = ssAddr
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

		payload := fmt.Sprintf("hello-ssproxy-socks5-%d-%s", i, strings.Repeat("x", 64))
		if _, err := conn.Write([]byte(payload)); err != nil {
			conn.Close()
			cliCfg.Close()
			t.Fatalf("client %d: write: %v", i, err)
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 2048)
		n, err := ss.ReadN(conn, buf, nil)
		if err != nil {
			conn.Close()
			cliCfg.Close()
			t.Fatalf("client %d: read: %v", i, err)
		}

		got := string(buf[:n])
		if got != payload {
			t.Errorf("client %d: echo mismatch:\n  want: %q\n  got:  %q", i, payload, got)
		}

		conn.Close()
		cliCfg.Close()
	}
}
