package server

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// TestSocksProxyWithSSProxy_Integration verifies the full socksproxy+ssproxy flow:
// client → SS encrypt → socksproxy+ssproxy (decrypt then direct to target).
func TestSocksProxyWithSSProxy_Integration(t *testing.T) {
	// Start an echo server as the final target
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

	// Start socksproxy+ssproxy using Listen to get the actual address
	ssCfg := &ss.Config{}
	ssCfg.Type = "socksproxy"
	ssCfg.Method = "aes-128-gcm"
	ssCfg.Password = "test123"
	ssCfg.SSProxy = true
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
	cliCfg.Password = "test123"
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

	// Send HTTP GET request through the proxy chain
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
