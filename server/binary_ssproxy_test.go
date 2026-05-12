package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func binaryPath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "..", "cmd", "shadowsocks", "shadowsocks.exe")
	if _, err := os.Stat(bin); err != nil {
		t.Skip("binary not found at", bin, " (run: go build -o shadowsocks.exe . in cmd/shadowsocks)")
	}
	return bin
}

// TestBinary_SSProxyWithBackend verifies the full chain with actual binaries:
//
//	browser → local SS client → SS encrypt → socksproxy+ssproxy
//	  → SS re-encrypt → backend SS server → echo
func TestBinary_SSProxyWithBackend(t *testing.T) {
	bin := binaryPath(t)

	const (
		echoPort        = 19998
		backendPort     = 19997
		socksProxyPort  = 19996
		localClientPort = 19995
	)

	// ---- 1. Echo server ----
	echoLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	defer echoLn.Close()
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

	// ---- 2. Backend SS server config ----
	backendCfg := map[string]any{
		"type":      "server",
		"localaddr": fmt.Sprintf("127.0.0.1:%d", backendPort),
		"method":    "aes-128-gcm",
		"password":  "backend-pass",
		"timeout":   10,
	}
	backendCfgPath := filepath.Join(t.TempDir(), "backend.json")
	backendData, _ := json.MarshalIndent(backendCfg, "", "  ")
	os.WriteFile(backendCfgPath, backendData, 0644)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	backendCmd := exec.CommandContext(ctx, bin, "-c", backendCfgPath)
	backendCmd.Stdout = os.Stdout
	backendCmd.Stderr = os.Stderr
	if err := backendCmd.Start(); err != nil {
		t.Fatalf("start backend: %v", err)
	}
	defer backendCmd.Process.Kill()

	if !waitForPort(t, "127.0.0.1", backendPort, 5*time.Second) {
		t.Fatal("backend SS server did not start")
	}
	t.Log("backend SS server started")

	// ---- 3. Socksproxy with backend ----
	socksCfg := map[string]any{
		"type":      "socksproxy",
		"localaddr": fmt.Sprintf("127.0.0.1:%d", socksProxyPort),
		"method":    "aes-128-gcm",
		"password":  "frontend-pass",
		"ssproxy":   true,
		"debug":     true,
		"timeout":   10,
		"backends": []map[string]any{
			{
				"remoteaddr": fmt.Sprintf("127.0.0.1:%d", backendPort),
				"method":     "aes-128-gcm",
				"password":   "backend-pass",
			},
		},
	}
	socksCfgPath := filepath.Join(t.TempDir(), "socksproxy.json")
	socksData, _ := json.MarshalIndent(socksCfg, "", "  ")
	os.WriteFile(socksCfgPath, socksData, 0644)

	socksCmd := exec.CommandContext(ctx, bin, "-c", socksCfgPath)
	socksCmd.Stdout = os.Stdout
	socksCmd.Stderr = os.Stderr
	if err := socksCmd.Start(); err != nil {
		t.Fatalf("start socksproxy: %v", err)
	}
	defer socksCmd.Process.Kill()

	if !waitForPort(t, "127.0.0.1", socksProxyPort, 5*time.Second) {
		t.Fatal("socksproxy did not start")
	}
	t.Log("socksproxy started")

	// ---- 4. Local SS client ----
	localArgs := []string{
		"-l", fmt.Sprintf("127.0.0.1:%d", localClientPort),
		"-s", fmt.Sprintf("127.0.0.1:%d", socksProxyPort),
		"-p", "frontend-pass",
		"-m", "aes-128-gcm",
	}
	localCmd := exec.CommandContext(ctx, bin, localArgs...)
	localCmd.Stdout = os.Stdout
	localCmd.Stderr = os.Stderr
	if err := localCmd.Start(); err != nil {
		t.Fatalf("start local client: %v", err)
	}
	defer localCmd.Process.Kill()

	if !waitForPort(t, "127.0.0.1", localClientPort, 5*time.Second) {
		t.Fatal("local client did not start")
	}
	t.Log("local client started")

	// ---- 5. Test through the chain ----
	for i := range 3 {
		t.Run(fmt.Sprintf("conn_%d", i), func(t *testing.T) {
			testSocksConnection(t, localClientPort, echoPort)
		})
	}
}

func testSocksConnection(t *testing.T, proxyPort, targetPort int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial local proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("socks5 greeting write: %v", err)
	}
	greetingResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetingResp); err != nil {
		t.Fatalf("socks5 greeting read: %v", err)
	}
	if greetingResp[0] != 0x05 || greetingResp[1] != 0x00 {
		t.Fatalf("socks5 greeting: got %x", greetingResp)
	}

	// SOCKS5 CONNECT request
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, net.ParseIP("127.0.0.1").To4()...)
	req = append(req, byte(targetPort>>8), byte(targetPort&0xff))
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("socks5 request write: %v", err)
	}

	reqResp := make([]byte, 10)
	if _, err := io.ReadFull(conn, reqResp); err != nil {
		t.Fatalf("socks5 request read: %v", err)
	}
	if reqResp[1] != 0x00 {
		t.Fatalf("socks5 request rejected: 0x%02x", reqResp[1])
	}

	// Send payload, read echo
	payload := fmt.Sprintf("hello-ssproxy-binary-%d", time.Now().UnixNano())
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var resp bytes.Buffer
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			resp.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF || (isTimeout(err) && resp.Len() > 0) {
				break
			}
			t.Fatalf("read response: %v", err)
		}
	}

	got := resp.String()
	if !strings.Contains(got, payload) {
		t.Errorf("echo mismatch:\n  payload: %q\n  response: %q", payload, got)
	} else {
		t.Logf("roundtrip OK: %q echoed back", payload[:20])
	}
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}

func waitForPort(t *testing.T, host string, port int, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}
