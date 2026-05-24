package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
)

var echoBufPool = &sync.Pool{New: func() any { b := make([]byte, 65536); return &b }}

var quickCommand = &cli.Command{
	Name:      "quick",
	Usage:     "run a single-scenario throughput benchmark",
	ArgsUsage: "<binary> <method> <password>",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "latency", Usage: "report latency percentiles"},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() < 3 {
			return fmt.Errorf("usage: bench quick <binary> <method> <password> [-latency]")
		}
		return runQuick(c.Args().Get(0), c.Args().Get(1), c.Args().Get(2), c.Bool("latency"))
	},
}

func runQuick(bin, method, password string, wantLatency bool) error {
	echoPort := freePort()
	ssPort := freePort()
	socksPort := freePort()

	echoLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
	if err != nil {
		return fmt.Errorf("echo listen: %w", err)
	}
	go runEchoBench(echoLn)

	td := ccTempDir()
	srvCfg := fmt.Sprintf(`{"type":"server","localaddr":"127.0.0.1:%d","method":"%s","password":"%s"}`, ssPort, method, password)
	srvFile := fmt.Sprintf("%s/ss-srv-%d.json", td, os.Getpid())
	os.WriteFile(srvFile, []byte(srvCfg), 0644)
	defer os.Remove(srvFile)

	cliCfg := fmt.Sprintf(`{"type":"local","localaddr":"127.0.0.1:%d","remoteaddr":"127.0.0.1:%d","method":"%s","password":"%s","udprelay":false}`, socksPort, ssPort, method, password)
	cliFile := fmt.Sprintf("%s/ss-cli-%d.json", td, os.Getpid())
	os.WriteFile(cliFile, []byte(cliCfg), 0644)
	defer os.Remove(cliFile)

	srvCmd := exec.Command(bin, "-c", srvFile)
	srvCmd.Env = append(os.Environ(), "GODEBUG=gctrace=1")
	gcReader, _ := srvCmd.StderrPipe()
	srvCmd.Stdout = io.Discard
	if err := srvCmd.Start(); err != nil {
		return fmt.Errorf("start server: %w", err)
	}
	defer srvCmd.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	cliCmd := exec.Command(bin, "-c", cliFile)
	cliCmd.Stdout = io.Discard
	cliCmd.Stderr = io.Discard
	if err := cliCmd.Start(); err != nil {
		return fmt.Errorf("start client: %w", err)
	}
	defer cliCmd.Process.Kill()
	time.Sleep(500 * time.Millisecond)

	gcDone := make(chan gcStats, 1)
	go func() { gcDone <- parseGCBench(gcReader) }()

	cpuDone := make(chan float64, 1)
	go func() { cpuDone <- sampleCPUBench(srvCmd.Process.Pid, 20*time.Second) }()

	self, _ := os.Executable()
	loadArgs := []string{"load",
		"-socks", fmt.Sprintf("127.0.0.1:%d", socksPort),
		"-target", fmt.Sprintf("127.0.0.1:%d", echoPort),
		"-c", "100", "-d", "20s", "-size", "4096",
	}
	if wantLatency {
		loadArgs = append(loadArgs, "-latency")
	}
	ploadOut, _ := exec.Command(self, loadArgs...).Output()
	ploadStr := string(ploadOut)

	srvCmd.Process.Kill()
	cliCmd.Process.Kill()

	gc := <-gcDone
	cpu := <-cpuDone
	tput := parseThroughputBench(ploadStr)
	lat := parseLatencyBench(ploadStr)

	if wantLatency {
		fmt.Printf("%.1f %.1f %d %.2f %.0f %.1f %.3f %.3f %.3f %.3f %.3f %.3f\n",
			tput, cpu, gc.n, gc.clock, gc.maxHeap, gc.avgAfter,
			lat.fbP50, lat.fbP95, lat.fbP99, lat.rttP50, lat.rttP95, lat.rttP99)
	} else {
		fmt.Printf("%.1f %.1f %d %.2f %.0f %.1f\n", tput, cpu, gc.n, gc.clock, gc.maxHeap, gc.avgAfter)
	}
	return nil
}

func ccTempDir() string {
	dir := os.Getenv("CC_TMP")
	if dir == "" {
		dir = "/tmp/cc-shadowsocks-go"
	}
	os.MkdirAll(dir, 0755)
	return dir
}

func runEchoBench(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			buf := echoBufPool.Get().(*[]byte)
			defer echoBufPool.Put(buf)
			io.CopyBuffer(c, c, *buf)
		}(conn)
	}
}

type gcStats struct {
	n        int
	clock    float64
	maxHeap  float64
	avgAfter float64
	allocMB  float64
}

type latResult struct{ fbP50, fbP95, fbP99, rttP50, rttP95, rttP99 float64 }

func freePort() int {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func parseGCBench(r io.Reader) gcStats {
	var s gcStats
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "gc ") {
			continue
		}
		s.n++
		if idx := strings.Index(line, "->"); idx > 0 {
			if mb := strings.Index(line[idx:], " MB"); mb > 0 {
				heapPart := line[idx-1 : idx+mb+3]
				if space := strings.LastIndexByte(heapPart[:len(heapPart)-3], ' '); space >= 0 {
					heapPart = heapPart[space+1 : len(heapPart)-3]
				}
				parts := strings.SplitN(heapPart, "->", 3)
				if len(parts) == 3 {
					before, _ := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
					after, _ := strconv.ParseFloat(strings.TrimSpace(parts[2]), 64)
					s.avgAfter += after
					if before > s.maxHeap {
						s.maxHeap = before
					}
				}
			}
		}
		if i := strings.Index(line, " ms clock"); i > 0 {
			j := i
			for j > 0 && line[j-1] != ' ' {
				j--
			}
			for _, part := range strings.Split(line[j:i], "+") {
				ms, _ := strconv.ParseFloat(strings.TrimSpace(part), 64)
				s.clock += ms
			}
		}
		// Parse cumulative alloc from "V MB alloc" field (Go 1.22+)
		if i := strings.Index(line, " MB alloc"); i > 0 {
			j := i
			for j > 0 && line[j-1] != ' ' {
				j--
			}
			if v, err := strconv.ParseFloat(strings.TrimSpace(line[j:i]), 64); err == nil {
				s.allocMB = v
			}
		}
	}
	if s.n > 0 {
		s.avgAfter /= float64(s.n)
	}
	return s
}

func sampleCPUBench(pid int, dur time.Duration) float64 {
	sum, n := 0.0, 0
	deadline := time.Now().Add(dur)
	for time.Now().Before(deadline) {
		out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "%cpu=").Output()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}
		v, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
		sum += v
		n++
		time.Sleep(500 * time.Millisecond)
	}
	if n == 0 {
		return 0
	}
	return sum / float64(n)
}

func parseThroughputBench(out string) float64 {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Throughput:") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				v, _ := strconv.ParseFloat(f[1], 64)
				return v
			}
		}
	}
	return 0
}

func parseLatencyBench(out string) latResult {
	var r latResult
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "LATENCY ") {
			continue
		}
		for _, f := range strings.Fields(line)[1:] {
			kv := strings.SplitN(f, "=", 2)
			if len(kv) != 2 {
				continue
			}
			v, _ := strconv.ParseFloat(strings.TrimSuffix(kv[1], "us"), 64)
			switch kv[0] {
			case "fb_p50":
				r.fbP50 = v
			case "fb_p95":
				r.fbP95 = v
			case "fb_p99":
				r.fbP99 = v
			case "rtt_p50":
				r.rttP50 = v
			case "rtt_p95":
				r.rttP95 = v
			case "rtt_p99":
				r.rttP99 = v
			}
		}
	}
	return r
}
