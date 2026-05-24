package main

import (
	"encoding/json"
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
	"github.com/urfave/cli/v2"
)

var virtCommand = &cli.Command{
	Name:  "virt",
	Usage: "virtual service data-flow test",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Required: true, Usage: "JSON config file path"},
	},
	Action: func(c *cli.Context) error {
		return runVirt(c.String("config"))
	},
}

func runVirt(configFile string) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}

	var cfgs []*ss.Config
	if err := json.Unmarshal(data, &cfgs); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	for _, c := range cfgs {
		ss.CheckConfig(c)
	}

	type listenerKey struct {
		idx  int
		addr string
	}
	listeners := make(map[listenerKey]net.Listener)
	realAddrs := make(map[string]string)

	for i, cfg := range cfgs {
		addr := cfg.Localaddr
		if addr != "" && !strings.HasPrefix(addr, "@") {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return fmt.Errorf("listen %s: %w", addr, err)
			}
			listeners[listenerKey{i, addr}] = ln
			placeholder := fmt.Sprintf("__CFG%d__", i)
			realAddrs[placeholder] = ln.Addr().String()
			if _, exists := realAddrs[addr]; !exists {
				realAddrs[addr] = realAddrs[placeholder]
			}
		}
	}

	for i, cfg := range cfgs {
		cfg.Localaddr = fmt.Sprintf("__CFG%d__", i)
	}
	for _, cfg := range cfgs {
		if real, ok := realAddrs[cfg.Localaddr]; ok {
			cfg.Localaddr = real
		}
		if real, ok := realAddrs[cfg.Remoteaddr]; ok {
			cfg.Remoteaddr = real
		}
		if cfg.Backend != nil {
			if real, ok := realAddrs[cfg.Backend.Remoteaddr]; ok {
				cfg.Backend.Remoteaddr = real
			}
		}
	}

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("echo listen: %w", err)
	}
	echoAddr := echoLn.Addr().String()
	_, echoPortStr, _ := net.SplitHostPort(echoAddr)
	echoPort, _ := strconv.Atoi(echoPortStr)
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

	fmt.Println("=== itest virt: virtual service data flow verification ===")
	fmt.Printf("echo server: %s\n\n", echoAddr)

	for i, cfg := range cfgs {
		var ln net.Listener
		for key, l := range listeners {
			if key.idx == i {
				ln = l
				break
			}
		}
		startVirtServer(cfg, ln, echoAddr, echoPort)
	}
	defer func() {
		for _, cfg := range cfgs {
			cfg.Close()
		}
		for _, ln := range listeners {
			ln.Close()
		}
	}()

	time.Sleep(time.Second)

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
	for _, cfg := range cfgs {
		addIfVirtual(allNames, cfg.RtunnelService)
		for _, b := range cfg.Backends {
			addIfVirtual(allNames, b.RtunnelService)
		}
	}

	for name := range allNames {
		if isRtunnelService(cfgs, name) {
			fmt.Printf("\n--- Testing rtunnel service %s (waiting for smux setup) ---\n", name)
			time.Sleep(2 * time.Second)
		} else {
			fmt.Printf("\n--- Testing virtual service %s ---\n", name)
		}
		if testVirtService(name, echoAddr, echoPort) {
			passed++
			fmt.Println("  PASS")
		} else {
			failed++
			fmt.Println("  FAIL")
		}
	}

	fmt.Printf("\n=== Results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
	return nil
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

func startVirtServer(cfg *ss.Config, ln net.Listener, echoAddr string, echoPort int) {
	switch cfg.Type {
	case "server":
		fmt.Printf("start server on %s (method=%s)\n", cfg.Localaddr, cfg.Method)
		if ln != nil {
			go runVirtSrvListener(ln, cfg)
		} else {
			go server.RunTCPRemoteServer(cfg)
		}
	case "local":
		fmt.Printf("start local SOCKS on %s -> %s (method=%s)\n", cfg.Localaddr, cfg.Remoteaddr, cfg.Method)
		go server.RunTCPLocalServer(cfg)
	case "multiserver":
		fmt.Printf("start multiserver on %s\n", cfg.Localaddr)
		if ln != nil {
			go runVirtSrvListener(ln, cfg)
		} else {
			go server.RunMultiTCPRemoteServer(cfg)
		}
	case "ssproxy":
		fmt.Printf("start ssproxy on %s -> %s (method=%s)\n", cfg.Localaddr, cfg.Remoteaddr, cfg.Method)
		if ln != nil {
			go runVirtProxyListener(ln, cfg)
		} else {
			go server.RunSSProxyServer(cfg)
		}
	case "rtunnelserver":
		fmt.Printf("start rtunnel server on %s\n", cfg.Localaddr)
		if ln != nil {
			go runVirtRtunnelListener(ln, cfg)
		} else {
			go server.RunRtunnelServer(cfg)
		}
	case "rtunnelclient":
		fmt.Printf("start rtunnel client -> %s (target=%s)\n", cfg.Backend.Remoteaddr, cfg.Remoteaddr)
		if !strings.Contains(cfg.Remoteaddr, ":") {
			cfg.Remoteaddr = echoAddr
		}
		go server.RunRtunnelClient(cfg)
	case "wstunnel":
		fmt.Printf("start wstunnel on %s\n", cfg.Localaddr)
		if ln != nil {
			go runVirtWstunnelListener(ln, cfg)
		} else {
			go server.RunWstunnelRemoteServer(cfg)
		}
	}
}

func runVirtSrvListener(ln net.Listener, cfg *ss.Config) {
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(cfg.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}
	lis := ss.NewListener(ln, cfg, handlers)
	defer lis.Close()
	go func() { <-cfg.DieChan(); lis.Close() }()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go server.RemoteHandler(conn.(*ss.AcceptedConn))
	}
}

func runVirtProxyListener(ln net.Listener, cfg *ss.Config) {
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(cfg.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}
	lis := ss.NewListener(ln, cfg, handlers)
	defer lis.Close()
	go func() { <-cfg.DieChan(); lis.Close() }()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go server.SSProxyHandler(conn.(*ss.AcceptedConn))
	}
}

func runVirtRtunnelListener(ln net.Listener, cfg *ss.Config) {
	var handlers []ss.AcceptHandler
	if len(cfg.Backends) == 0 {
		handlers = []ss.AcceptHandler{ss.LimitHandler}
		if crypto.IsAEAD2022(cfg.Method) {
			handlers = append(handlers, ss.SS2022Handler)
		} else {
			handlers = append(handlers, ss.SSHandler)
		}
	} else {
		handlers = []ss.AcceptHandler{ss.LimitHandler, ss.SSMultiHandler}
	}
	lis := ss.NewListener(ln, cfg, handlers)
	defer lis.Close()
	go func() { <-cfg.DieChan(); lis.Close() }()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go server.RtunnelHandler(conn.(*ss.AcceptedConn))
	}
}

func runVirtWstunnelListener(ln net.Listener, cfg *ss.Config) {
	handlers := []ss.AcceptHandler{ss.LimitHandler}
	if crypto.IsAEAD2022(cfg.Method) {
		handlers = append(handlers, ss.SS2022Handler)
	} else {
		handlers = append(handlers, ss.SSHandler)
	}
	lis := ss.NewListener(ln, cfg, handlers)
	defer lis.Close()
	go func() { <-cfg.DieChan(); lis.Close() }()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go server.RemoteHandler(conn.(*ss.AcceptedConn))
	}
}

func testVirtService(name, echoAddr string, echoPort int) bool {
	echoHost, _, _ := net.SplitHostPort(echoAddr)
	conn, err := ss.DialVirtual(name)
	if err != nil {
		fmt.Printf("  DialVirtual error: %v\n", err)
		return false
	}
	defer conn.Close()
	if ok := testViaSOCKS5(conn, echoHost, echoPort); ok {
		return true
	}
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
		fmt.Printf("  echo mismatch\n")
		return false
	}
	fmt.Printf("  SOCKS5 echo OK\n")
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
		fmt.Printf("  raw echo mismatch\n")
		return false
	}
	fmt.Printf("  raw echo OK\n")
	return true
}
