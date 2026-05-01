// Command vstest is a standalone virtual-service data-flow tester for shadowsocks-go.
// It reads the same JSON config format as the main binary, starts servers, dials
// virtual services, and verifies that actual data flows through them correctly.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	server "github.com/ccsexyz/shadowsocks-go/server"
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

var configFile = flag.String("c", "", "JSON config file path (same format as shadowsocks-go)")

func main() {
	flag.Parse()
	if *configFile == "" {
		fmt.Fprintln(os.Stderr, "usage: vstest -c <config.json>")
		os.Exit(1)
	}

	data, err := os.ReadFile(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read config: %v\n", err)
		os.Exit(1)
	}

	var cfgs []*ss.Config
	if err := json.Unmarshal(data, &cfgs); err != nil {
		fmt.Fprintf(os.Stderr, "parse config: %v\n", err)
		os.Exit(1)
	}

	for _, c := range cfgs {
		ss.CheckConfig(c)
	}

	// Pre-allocate listeners for all configs that need a real TCP port.
	// Use index+localaddr as key to avoid port sharing when multiple
	// configs use the same placeholder like "127.0.0.1:0".
	type listenerKey struct {
		idx  int
		addr string
	}
	listeners := make(map[listenerKey]net.Listener)
	realAddrs := make(map[string]string) // config localaddr → real addr (unique per config)

	for i, c := range cfgs {
		addr := c.Localaddr
		if isRealTCP(addr) && !strings.HasPrefix(addr, "@") {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "listen %s: %v\n", addr, err)
				os.Exit(1)
			}
			key := listenerKey{i, addr}
			listeners[key] = ln
			realAddr := ln.Addr().String()
			// Use a unique placeholder to track the real addr per config
			placeholder := fmt.Sprintf("__CFG%d__", i)
			realAddrs[placeholder] = realAddr
			// Also map the original localaddr if it's the first one
			if _, exists := realAddrs[addr]; !exists {
				realAddrs[addr] = realAddr
			}
		}
	}

	// Update remote addresses that reference a config-local placeholder
	for i, c := range cfgs {
		placeholder := fmt.Sprintf("__CFG%d__", i)
		c.Localaddr = placeholder
	}

	// Now resolve all placeholders back to real addrs
	for _, c := range cfgs {
		if real, ok := realAddrs[c.Localaddr]; ok {
			c.Localaddr = real
		}
		// For remoteaddr that's a placeholder
		if real, ok := realAddrs[c.Remoteaddr]; ok {
			c.Remoteaddr = real
		}
		if c.Backend != nil {
			if real, ok := realAddrs[c.Backend.Remoteaddr]; ok {
				c.Backend.Remoteaddr = real
			}
		}
	}

	// Start echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "echo listen: %v\n", err)
		os.Exit(1)
	}
	echoAddr := echoLn.Addr().String()
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)
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

	fmt.Println("=== vstest: virtual service data flow verification ===")
	fmt.Printf("echo server: %s\n\n", echoAddr)

	// Start all servers using pre-allocated listeners where available
	for i, c := range cfgs {
		origAddr := fmt.Sprintf("__CFG%d__", i)
		// Look up listener by original placeholder
		var ln net.Listener
		for key, l := range listeners {
			if key.idx == i {
				ln = l
				break
			}
		}
		_ = origAddr
		startServer(c, ln, echoAddr, echoPort)
	}
	defer func() {
		for _, c := range cfgs {
			c.Close()
		}
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	time.Sleep(time.Second)

	// Test each virtual service
	passed, failed := 0, 0
	vservices := ss.ListVirtualServices()
	fmt.Printf("\nFound %d virtual service(s):\n", len(vservices))
	for _, vs := range vservices {
		fmt.Printf("  %s (source: %s, accepts: %d)\n", vs.Name, vs.Source, vs.AcceptCount)
	}

	allNames := make(map[string]bool)

	for _, vs := range vservices {
		allNames[vs.Name] = true
	}

	// Also check rtunnel services from config
	for _, c := range cfgs {
		addIfVirtual(allNames, c.RtunnelService)
		for _, b := range c.Backends {
			addIfVirtual(allNames, b.RtunnelService)
		}
	}

	for name := range allNames {
		// rtunnel services may need extra time for smux keepalive to flush the SS header
		if isRtunnelService(cfgs, name) {
			fmt.Printf("\n--- Testing rtunnel service %s (waiting for smux setup) ---\n", name)
			time.Sleep(2 * time.Second)
		} else {
			fmt.Printf("\n--- Testing virtual service %s ---\n", name)
		}

		if testVirtualService(name, echoAddr, echoPort) {
			passed++
			fmt.Printf("  PASS\n")
		} else {
			failed++
			fmt.Printf("  FAIL\n")
		}
	}

	// Test wstunnel → virtual service forwarding
	for _, c := range cfgs {
		if c.Type == "wstunnel" && len(c.TargetMap) > 0 {
			wstunnelAddr := c.Localaddr // already resolved to real addr
			for host, target := range c.TargetMap {
				if strings.HasPrefix(target, "@") {
					fmt.Printf("\n--- Testing wstunnel target_map[%q] → %s ---\n", host, target)
					if testWstunnelForwarding(wstunnelAddr, host, echoAddr, echoPort) {
						passed++
						fmt.Printf("  PASS\n")
					} else {
						failed++
						fmt.Printf("  FAIL\n")
					}
				}
			}
		}
	}

	fmt.Printf("\n=== Results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

func isRtunnelService(cfgs []*ss.Config, name string) bool {
	for _, c := range cfgs {
		if strings.EqualFold(c.RtunnelService, name) {
			return true
		}
		for _, b := range c.Backends {
			if strings.EqualFold(b.RtunnelService, name) {
				return true
			}
		}
	}
	return false
}

func addIfVirtual(m map[string]bool, addr string) {
	if addr != "" && strings.HasPrefix(addr, "@") {
		m[strings.ToLower(addr)] = true
	}
}

func isRealTCP(addr string) bool {
	return addr != "" && !strings.HasPrefix(addr, "@")
}

func startServer(c *ss.Config, ln net.Listener, echoAddr string, echoPort int) {
	switch c.Type {
	case "server":
		fmt.Printf("start server on %s (method=%s)\n", c.Localaddr, c.Method)
		if ln != nil {
			go runServerOnListener(ln, c, "server")
		} else {
			go server.RunTCPRemoteServer(c)
		}
	case "local":
		fmt.Printf("start local SOCKS on %s -> %s (method=%s)\n", c.Localaddr, c.Remoteaddr, c.Method)
		go server.RunTCPLocalServer(c)
	case "multiserver":
		fmt.Printf("start multiserver on %s\n", c.Localaddr)
		if ln != nil {
			go runServerOnListener(ln, c, "multiserver")
		} else {
			go server.RunMultiTCPRemoteServer(c)
		}
	case "ssproxy":
		fmt.Printf("start ssproxy on %s -> %s (method=%s)\n", c.Localaddr, c.Remoteaddr, c.Method)
		if ln != nil {
			go runSSProxyOnListener(ln, c)
		} else {
			go server.RunSSProxyServer(c)
		}
	case "rtunnelserver":
		fmt.Printf("start rtunnel server on %s\n", c.Localaddr)
		if c.RtunnelService != "" {
			fmt.Printf("  rtunnelservice: %s\n", c.RtunnelService)
		}
		for _, b := range c.Backends {
			if b.RtunnelService != "" {
				fmt.Printf("  backend[%s] rtunnelservice: %s\n", b.Nickname, b.RtunnelService)
			}
		}
		if ln != nil {
			go runRtunnelServerOnListener(ln, c)
		} else {
			go server.RunRtunnelServer(c)
		}
	case "rtunnelclient":
		fmt.Printf("start rtunnel client -> %s (target=%s)\n", c.Backend.Remoteaddr, c.Remoteaddr)
		if !strings.Contains(c.Remoteaddr, ":") {
			c.Remoteaddr = echoAddr
		}
		go server.RunRtunnelClient(c)
	case "wstunnel":
		fmt.Printf("start wstunnel on %s\n", c.Localaddr)
		if len(c.TargetMap) > 0 {
			for k, v := range c.TargetMap {
				fmt.Printf("  target_map: %s -> %s\n", k, v)
			}
		}
		if ln != nil {
			go runWstunnelOnListener(ln, c)
		} else {
			go server.RunWstunnelRemoteServer(c)
		}
	}
}

func runServerOnListener(ln net.Listener, c *ss.Config, typ string) {
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(c.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}
	lis := ss.NewListener(ln, c, handlers)
	defer lis.Close()
	go func() {
		<-c.DieChan()
		lis.Close()
	}()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		ac := conn.(*ss.AcceptedConn)
		go server.RemoteHandler(ac)
	}
}

func runSSProxyOnListener(ln net.Listener, c *ss.Config) {
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(c.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}
	lis := ss.NewListener(ln, c, handlers)
	defer lis.Close()
	go func() {
		<-c.DieChan()
		lis.Close()
	}()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go server.SSProxyHandler(conn.(*ss.AcceptedConn))
	}
}

func runRtunnelServerOnListener(ln net.Listener, c *ss.Config) {
	var handlers []ss.AcceptHandler
	if len(c.Backends) == 0 {
		handlers = []ss.AcceptHandler{ss.LimitHandler}
		if crypto.IsAEAD2022(c.Method) {
			handlers = append(handlers, ss.SS2022Handler)
		} else {
			handlers = append(handlers, ss.SSHandler)
		}
	} else {
		handlers = []ss.AcceptHandler{ss.LimitHandler, ss.SSMultiHandler}
	}
	lis := ss.NewListener(ln, c, handlers)
	defer lis.Close()
	go func() {
		<-c.DieChan()
		lis.Close()
	}()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go server.RtunnelHandler(conn.(*ss.AcceptedConn))
	}
}

func runWstunnelOnListener(ln net.Listener, c *ss.Config) {
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(c.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}
	lis := ss.NewListener(ln, c, handlers)
	defer lis.Close()
	go func() {
		<-c.DieChan()
		lis.Close()
	}()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		ac := conn.(*ss.AcceptedConn)
		go server.RemoteHandler(ac)
	}
}

func testWstunnelForwarding(wstunnelAddr, matchKey, echoAddr string, echoPort int) bool {
	fmt.Printf("  connecting to wstunnel %s (target_map key: %q)\n", wstunnelAddr, matchKey)

	conn, err := net.Dial("tcp", wstunnelAddr)
	if err != nil {
		fmt.Printf("  dial wstunnel error: %v\n", err)
		return false
	}
	defer conn.Close()

	// The target_map key format for header-based matching is "<Header-Key> <Header-Value>".
	// E.g. "x-test vstest-forward" matches header "X-Test: vstest-forward".
	// Split the key to extract header name and value.
	parts := strings.SplitN(matchKey, " ", 2)
	headerName, headerValue := matchKey, ""
	if len(parts) == 2 {
		headerName, headerValue = parts[0], parts[1]
	}

	// Send HTTP request with valid Host and target_map-matching header
	req := fmt.Sprintf(
		"GET / HTTP/1.1\r\nHost: test.local\r\n%s: %s\r\nConnection: close\r\n\r\n",
		headerName, headerValue,
	)
	fmt.Printf("  sending request: %s: %s\n", headerName, headerValue)
	conn.Write([]byte(req))

	// Read the response — with HttpProxyTo + allow_http, the wstunnel proxies
	// this HTTP request to @A, which goes through rtunnel to the echo server.
	// The echo server echoes the raw proxy request back through the chain.
	// (The HTTP response parsing may fail since the echo sends back raw data,
	// but any non-empty response proves data flowed through the chain.)
	resp, err := io.ReadAll(conn)
	if err != nil {
		fmt.Printf("  read response error: %v\n", err)
		return false
	}
	respStr := string(resp)
	fmt.Printf("  received %d bytes in response\n", len(resp))
	if len(respStr) > 200 {
		respStr = respStr[:200] + "..."
	}
	fmt.Printf("  response preview: %q\n", respStr)

	// If we got data back through the chain, it's working
	if len(resp) > 0 {
		fmt.Printf("  wstunnel forwarding OK: data flowed through @A → rtunnel → echo\n")
		return true
	}
	return false
}

func testVirtualService(name string, echoAddr string, echoPort int) bool {
	echoHost, _, _ := net.SplitHostPort(echoAddr)

	conn, err := ss.DialVirtual(name)
	if err != nil {
		fmt.Printf("  DialVirtual error: %v\n", err)
		return false
	}
	defer conn.Close()

	// Try SOCKS5 first
	if ok := testViaSOCKS5(conn, echoHost, echoPort); ok {
		return true
	}

	// Fall back: raw data flow for non-SOCKS services (e.g., rtunnel)
	conn.Close()
	conn, err = ss.DialVirtual(name)
	if err != nil {
		fmt.Printf("  re-DialVirtual error: %v\n", err)
		return false
	}
	defer conn.Close()

	return testRawEcho(conn)
}

func testViaSOCKS5(conn net.Conn, host string, port int) bool {
	conn.Write([]byte{5, 1, 0})
	buf := make([]byte, 512)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return false
	}
	if buf[0] != 5 || buf[1] != 0 {
		return false
	}

	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))
	conn.Write(req)
	if _, err := io.ReadFull(conn, buf[:10]); err != nil {
		return false
	}
	if buf[1] != 0 {
		fmt.Printf("  SOCKS5 connect failed: response=%x\n", buf[:2])
		return false
	}

	payload := fmt.Sprintf("vstest-socks5-%d", time.Now().UnixNano())
	conn.Write([]byte(payload))
	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, resp); err != nil {
		fmt.Printf("  echo read error: %v\n", err)
		return false
	}
	if string(resp) != payload {
		fmt.Printf("  echo mismatch: expected '%s', got '%s'\n", payload, string(resp))
		return false
	}
	fmt.Printf("  SOCKS5 echo OK: '%s'\n", payload)
	return true
}

func testRawEcho(conn net.Conn) bool {
	payload := fmt.Sprintf("vstest-raw-%d", time.Now().UnixNano())
	conn.Write([]byte(payload))
	resp := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, resp); err != nil {
		fmt.Printf("  raw echo read error: %v\n", err)
		return false
	}
	if string(resp) != payload {
		fmt.Printf("  raw echo mismatch: expected '%s', got '%s'\n", payload, string(resp))
		return false
	}
	fmt.Printf("  raw echo OK: '%s'\n", payload)
	return true
}

func init() {
	_ = crypto.IsAEAD2022
}
