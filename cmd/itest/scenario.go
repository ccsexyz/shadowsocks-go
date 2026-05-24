package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
)

// Scenario describes a multi-service integration test.
type Scenario struct {
	Setup []ServiceSpec `json:"setup"`
	Tests []TestSpec    `json:"tests"`
}

type ServiceSpec struct {
	Type     string `json:"type"` // echo, ss_server, ss_local
	Addr     string `json:"addr,omitempty"`
	Server   string `json:"server,omitempty"` // for ss_local: upstream ss_server address
	Method   string `json:"method,omitempty"`
	Password string `json:"password,omitempty"`
	Socks    string `json:"socks,omitempty"`
	Delay    string `json:"delay,omitempty"`
}

type TestSpec struct {
	Tool     string `json:"tool"` // pkt
	Target   string `json:"target,omitempty"`
	Socks    string `json:"socks,omitempty"`
	Min      int    `json:"min,omitempty"`
	Max      int    `json:"max,omitempty"`
	Duration string `json:"duration,omitempty"`
	Interval string `json:"interval,omitempty"`
}

var scenarioCommand = &cli.Command{
	Name:  "run",
	Usage: "orchestrate a multi-service integration test from a JSON scenario file",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Required: true, Usage: "scenario JSON file"},
		&cli.StringFlag{Name: "binary", Aliases: []string{"b"}, Usage: "path to shadowsocks-go binary"},
	},
	Action: func(c *cli.Context) error {
		data, err := os.ReadFile(c.String("config"))
		if err != nil {
			return err
		}
		var sc Scenario
		if err := json.Unmarshal(data, &sc); err != nil {
			return fmt.Errorf("parse scenario: %w", err)
		}
		return runScenario(sc, c.String("binary"))
	},
}

func runScenario(sc Scenario, ssBinary string) error {
	var cleanups []func()
	defer func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start all services
	var echoAddr, socksAddr string
	for _, svc := range sc.Setup {
		switch svc.Type {
		case "echo":
			delay, _ := time.ParseDuration(svc.Delay)
			addr, cleanup, err := startEcho(delay)
			if err != nil {
				return fmt.Errorf("start echo: %w", err)
			}
			cleanups = append(cleanups, cleanup)
			echoAddr = addr
			if svc.Addr != "" {
				echoAddr = fmt.Sprintf("127.0.0.1:%s", portOf(svc.Addr))
			}
			fmt.Printf("[setup] echo on %s\n", addr)

		case "ss_server":
			if ssBinary == "" {
				return fmt.Errorf("--binary is required for ss_server")
			}
			port := portOf(svc.Addr)
			addr := fmt.Sprintf("127.0.0.1:%s", port)
			cmd := exec.CommandContext(ctx, ssBinary,
				"-type", "server",
				"-l", addr,
				"-m", svc.Method,
				"-p", svc.Password,
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				return fmt.Errorf("start ss_server: %w", err)
			}
			cleanups = append(cleanups, func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() })
			fmt.Printf("[setup] ss_server on %s (method=%s)\n", addr, svc.Method)
			time.Sleep(200 * time.Millisecond)

		case "ss_local":
			if ssBinary == "" {
				return fmt.Errorf("--binary is required for ss_local")
			}
			port := portOf(svc.Addr)
			addr := fmt.Sprintf("127.0.0.1:%s", port)
			serverAddr := fmt.Sprintf("127.0.0.1:%s", portOf(svc.Server))
			cmd := exec.CommandContext(ctx, ssBinary,
				"-type", "local",
				"-l", addr,
				"-s", serverAddr,
				"-m", svc.Method,
				"-p", svc.Password,
			)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			if err := cmd.Start(); err != nil {
				return fmt.Errorf("start ss_local: %w", err)
			}
			cleanups = append(cleanups, func() { cmd.Process.Signal(os.Interrupt); cmd.Wait() })
			socksAddr = addr
			fmt.Printf("[setup] ss_local socks5 on %s -> %s (method=%s)\n", addr, serverAddr, svc.Method)
			time.Sleep(200 * time.Millisecond)
		}
	}

	time.Sleep(500 * time.Millisecond)
	fmt.Println()

	// Run tests
	passed, failed := 0, 0
	var mu sync.Mutex
	for i, test := range sc.Tests {
		name := fmt.Sprintf("test-%d-%s", i+1, test.Tool)
		target := test.Target
		socks := test.Socks
		if target == "" {
			target = echoAddr
		}
		if socks == "" {
			socks = socksAddr
		}
		fmt.Printf("[%s] starting...\n", name)

		interval := test.Interval
		if interval == "" {
			interval = "1ms"
		}

		switch test.Tool {
		case "pkt":
			ok := runPktTest(target, socks, test.Min, test.Max, interval)
			mu.Lock()
			if ok {
				passed++
			} else {
				failed++
			}
			mu.Unlock()
			fmt.Printf("[%s] %s\n", name, passFail(ok))
		}
	}

	fmt.Printf("\n=== Scenario results: %d passed, %d failed ===\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
	return nil
}

func runPktTest(target, socks string, minSize, maxSize int, interval string) bool {
	self, _ := os.Executable()
	args := []string{"pkt", "-target", target, "-socks", socks, "-min", fmt.Sprint(minSize), "-max", fmt.Sprint(maxSize), "-interval", interval}
	cmd := exec.Command(self, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run() == nil
}

func portOf(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "0"
	}
	return port
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func init() {
	// Ensure io is used (for io.ReadFull in pkt.go compat)
	_ = io.ReadFull
}
