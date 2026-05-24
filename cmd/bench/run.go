package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
)

type config struct {
	Methods       []string          `json:"methods"`
	Payloads      []int             `json:"payloads"`
	Concurrencies []int             `json:"concurrencies"`
	Duration      string            `json:"duration"`
	Warmup        string            `json:"warmup"`
	Modes         []string          `json:"modes"`
	Password      string            `json:"password"`
	Passwords     map[string]string `json:"passwords"`
	Repeat        int               `json:"repeat"`
	BW            float64           `json:"bw"`
	Latency       bool              `json:"latency"`
	Jobs          int               `json:"jobs"`
}

type result struct {
	Method            string      `json:"method"`
	Payload           int         `json:"payload"`
	Concurrency       int         `json:"concurrency"`
	Mode              string      `json:"mode"`
	Repeat            int         `json:"repeat"`
	Throughput        float64     `json:"throughput_mbps"`
	CPU               float64     `json:"cpu_pct"`
	PprofCPU          float64     `json:"pprof_cpu_pct,omitempty"`
	GCCycles          int         `json:"gc_cycles"`
	GCClock           float64     `json:"gc_clock_ms"`
	MaxHeap           float64     `json:"max_heap_mb"`
	AvgHeap           float64     `json:"avg_heap_mb"`
	AllocMB           float64     `json:"alloc_mb"`
	PprofAllocs       []pprofSite `json:"pprof_allocs,omitempty"`
	PprofHeap         []pprofSite `json:"pprof_heap,omitempty"`
	PprofCPUSVG       string      `json:"pprof_cpu_svg,omitempty"`
	PprofAllocsSVG    string      `json:"pprof_allocs_svg,omitempty"`
	PprofHeapSVG      string      `json:"pprof_heap_svg,omitempty"`
	PprofCPUSVGRaw    string      `json:"pprof_cpu_svg_raw,omitempty"`
	PprofAllocsSVGRaw string      `json:"pprof_allocs_svg_raw,omitempty"`
	PprofHeapSVGRaw   string      `json:"pprof_heap_svg_raw,omitempty"`
	FbP50             float64     `json:"fb_p50_us,omitempty"`
	FbP95             float64     `json:"fb_p95_us,omitempty"`
	FbP99             float64     `json:"fb_p99_us,omitempty"`
	RttP50            float64     `json:"rtt_p50_us,omitempty"`
	ConnErrors        int         `json:"conn_errors,omitempty"`
	RttP95            float64     `json:"rtt_p95_us,omitempty"`
	RttP99            float64     `json:"rtt_p99_us,omitempty"`
	Error             string      `json:"error,omitempty"`
}

type pprofSite struct {
	Flat     float64 `json:"flat"`
	FlatPct  float64 `json:"flat_pct"`
	SumPct   float64 `json:"sum_pct"`
	Cum      float64 `json:"cum"`
	CumPct   float64 `json:"cum_pct"`
	Function string  `json:"function"`
}

var runCommand = &cli.Command{
	Name:      "run",
	Usage:     "run matrix benchmark",
	ArgsUsage: "<binary> <config.json>",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "output results JSON file"},
		&cli.IntFlag{Name: "jobs", Aliases: []string{"j"}, Usage: "max concurrent scenarios (default: 1)"},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() < 2 {
			return fmt.Errorf("usage: bench run <binary> <config.json> [-o results.json]")
		}
		bin := c.Args().Get(0)
		cfgFile := c.Args().Get(1)

		data, err := os.ReadFile(cfgFile)
		if err != nil {
			return fmt.Errorf("read config: %w", err)
		}
		var cfg config
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse config: %w", err)
		}
		if cfg.Modes == nil {
			cfg.Modes = []string{"server"}
		}
		if cfg.Duration == "" {
			cfg.Duration = "10s"
		}
		if cfg.Warmup == "" {
			cfg.Warmup = "3s"
		}
		if cfg.Repeat < 1 {
			cfg.Repeat = 1
		}
		if c.IsSet("jobs") {
			cfg.Jobs = c.Int("jobs")
		}

		results := runMatrix(bin, cfg)
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal results: %w", err)
		}
		if out := c.String("output"); out != "" {
			if err := os.WriteFile(out, b, 0644); err != nil {
				return fmt.Errorf("write %s: %w", out, err)
			}
		} else {
			os.Stdout.Write(b)
		}
		return nil
	},
}

func passwordFor(cfg config, method string) string {
	if pw, ok := cfg.Passwords[method]; ok {
		return pw
	}
	return cfg.Password
}

func runMatrix(bin string, cfg config) []result {
	var results []result
	var mu sync.Mutex
	var wg sync.WaitGroup
	jobs := cfg.Jobs
	if jobs <= 0 {
		jobs = 1
	}
	sem := make(chan struct{}, jobs) // limit concurrent scenarios

	loadBin, _ := os.Executable()
	if loadBin == "" {
		loadBin = bin
	}

	for _, method := range cfg.Methods {
		for _, payload := range cfg.Payloads {
			for _, conc := range cfg.Concurrencies {
				for _, mode := range cfg.Modes {
					for r := range cfg.Repeat {
						wg.Add(1)
						sem <- struct{}{}
						go func(method, mode string, payload, conc, rep int) {
							defer wg.Done()
							defer func() { <-sem }()
							res := runOne(bin, loadBin, method, passwordFor(cfg, method), mode, payload, conc, cfg.BW, cfg, rep)
							mu.Lock()
							results = append(results, res)
							mu.Unlock()
						}(method, mode, payload, conc, r)
					}
				}
			}
		}
	}
	wg.Wait()
	return results
}

func runOne(ssBin, loadBin, method, password, mode string, payload, conc int, bw float64, cfg config, rep int) result {
	res := result{Method: method, Payload: payload, Concurrency: conc, Mode: mode, Repeat: rep}

	isUDP := strings.HasSuffix(mode, "-udp")
	echoPort := freePort()
	ssPort := freePort()
	socksPort := freePort()

	td := ccTempDir()

	var echoLn net.Listener
	var echoUDPConn *net.UDPConn
	if isUDP {
		uaddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", echoPort))
		if err != nil {
			res.Error = fmt.Sprintf("resolve udp echo: %v", err)
			return res
		}
		echoUDPConn, err = net.ListenUDP("udp", uaddr)
		if err != nil {
			res.Error = fmt.Sprintf("udp echo listen: %v", err)
			return res
		}
		go runUDPEchoBench(echoUDPConn)
		defer echoUDPConn.Close()
	} else {
		echoLn, _ = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", echoPort))
		if echoLn == nil {
			res.Error = "echo listen failed"
			return res
		}
		go runEchoBench(echoLn)
		defer echoLn.Close()
	}

	udpFlag := "false"
	if isUDP {
		udpFlag = "true"
	}
	srvCfg := fmt.Sprintf(`{"type":"server","localaddr":"127.0.0.1:%d","method":"%s","password":"%s","udprelay":%s,"obfs":true,"obfsalive":true,"loghttp":true}`, ssPort, method, password, udpFlag)
	srvFile := fmt.Sprintf("%s/ss-srv-%d.json", td, os.Getpid())
	os.WriteFile(srvFile, []byte(srvCfg), 0644)
	defer os.Remove(srvFile)

	cliCfg := fmt.Sprintf(`{"type":"local","localaddr":"127.0.0.1:%d","remoteaddr":"127.0.0.1:%d","method":"%s","password":"%s","udprelay":%s,"obfs":true,"obfsalive":true,"loghttp":true}`, socksPort, ssPort, method, password, udpFlag)
	cliFile := fmt.Sprintf("%s/ss-cli-%d.json", td, os.Getpid())
	os.WriteFile(cliFile, []byte(cliCfg), 0644)
	defer os.Remove(cliFile)

	pprofPort := freePort()
	srvArgs := []string{"-type", "server", "-l", fmt.Sprintf("127.0.0.1:%d", ssPort), "-m", method, "-p", password, "-pprof", fmt.Sprintf("127.0.0.1:%d", pprofPort), "-filtcap", "1000000"}
	if isUDP {
		srvArgs = append(srvArgs, "-udprelay")
	}
	srvCmd := exec.Command(ssBin, srvArgs...)
	srvCmd.Env = append(os.Environ(), "GODEBUG=gctrace=1")
	gcReader, _ := srvCmd.StderrPipe()
	srvCmd.Stdout = io.Discard
	if err := srvCmd.Start(); err != nil {
		res.Error = fmt.Sprintf("start server: %v", err)
		return res
	}
	defer srvCmd.Process.Kill()
	time.Sleep(300 * time.Millisecond)

	cliArgs := []string{"-type", "local", "-l", fmt.Sprintf("127.0.0.1:%d", socksPort), "-s", fmt.Sprintf("127.0.0.1:%d", ssPort), "-m", method, "-p", password, "-filtcap", "1000000"}
	if isUDP {
		cliArgs = append(cliArgs, "-udprelay")
	}
	cliCmd := exec.Command(ssBin, cliArgs...)
	cliCmd.Stdout = io.Discard
	cliCmd.Stderr = io.Discard
	if err := cliCmd.Start(); err != nil {
		res.Error = fmt.Sprintf("start client: %v", err)
		return res
	}
	defer cliCmd.Process.Kill()
	time.Sleep(300 * time.Millisecond)

	dur, _ := time.ParseDuration(cfg.Duration)
	warmDur, _ := time.ParseDuration(cfg.Warmup)
	totalDur := dur + warmDur

	gcDone := make(chan gcStats, 1)
	go func() { gcDone <- parseGCBench(gcReader) }()

	cpuDone := make(chan float64, 1)
	go func() { cpuDone <- sampleCPUBench(srvCmd.Process.Pid, totalDur) }()

	pprofDone := make(chan float64, 1)
	if warmDur > 0 {
		if isUDP {
			runUDPLoadQuiet(loadBin, socksPort, echoPort, conc, warmDur, payload, bw, cfg.Latency)
		} else {
			runLoadQuiet(loadBin, socksPort, echoPort, conc, warmDur, payload, bw, cfg.Latency)
		}
	}
	go func() {
		profSecs := int(dur.Seconds()) - 1
		if profSecs < 1 {
			profSecs = 1
		}
		pprofDone <- fetchCPUFromProfile(pprofPort, profSecs, &res)
	}()

	var ploadOut string
	var ploadErr error
	if isUDP {
		ploadOut, ploadErr = runUDPLoadQuiet(loadBin, socksPort, echoPort, conc, dur, payload, bw, cfg.Latency)
	} else {
		ploadOut, ploadErr = runLoadQuiet(loadBin, socksPort, echoPort, conc, dur, payload, bw, cfg.Latency)
	}
	res.PprofCPU = <-pprofDone
	if ploadErr != nil {
		res.Error = fmt.Sprintf("load: %v", ploadErr)
	} else {
		res.Throughput = parseThroughputBench(ploadOut)
		res.ConnErrors = parseConnErrors(ploadOut)
		if cfg.Latency {
			lat := parseLatencyBench(ploadOut)
			res.FbP50 = lat.fbP50
			res.FbP95 = lat.fbP95
			res.FbP99 = lat.fbP99
			res.RttP50 = lat.rttP50
			res.RttP95 = lat.rttP95
			res.RttP99 = lat.rttP99
		} else {
		}
	}

	res.AllocMB = fetchAllocMB(pprofPort)
	collectPprof(pprofPort, &res)

	srvCmd.Process.Kill()
	cliCmd.Process.Kill()

	gc := <-gcDone
	cpu := <-cpuDone
	res.CPU = math.Round(cpu*10) / 10
	res.GCCycles = gc.n
	res.GCClock = math.Round(gc.clock*100) / 100
	res.MaxHeap = math.Round(gc.maxHeap*100) / 100
	res.AvgHeap = math.Round(gc.avgAfter*100) / 100

	return res
}

func runLoadQuiet(self string, socksPort, echoPort, conc int, dur time.Duration, payload int, bw float64, latency bool) (string, error) {
	args := []string{
		"load",
		"-socks", fmt.Sprintf("127.0.0.1:%d", socksPort),
		"-target", fmt.Sprintf("127.0.0.1:%d", echoPort),
		"-c", fmt.Sprint(conc),
		"-d", dur.String(),
		"-size", fmt.Sprint(payload),
	}
	if bw > 0 {
		args = append(args, "-bw", fmt.Sprint(bw))
	}
	if latency {
		args = append(args, "-latency")
	}
	out, err := exec.Command(self, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func runUDPLoadQuiet(self string, socksPort, echoPort, conc int, dur time.Duration, payload int, bw float64, latency bool) (string, error) {
	args := []string{
		"udpload",
		"-socks", fmt.Sprintf("127.0.0.1:%d", socksPort),
		"-target", fmt.Sprintf("127.0.0.1:%d", echoPort),
		"-c", fmt.Sprint(conc),
		"-d", dur.String(),
		"-size", fmt.Sprint(payload),
	}
	if bw > 0 {
		args = append(args, "-bw", fmt.Sprint(bw))
	}
	if latency {
		args = append(args, "-latency")
	}
	out, err := exec.Command(self, args...).Output()
	return strings.TrimSpace(string(out)), err
}

func runUDPEchoBench(conn *net.UDPConn) {
	buf := make([]byte, 65536+512) // room for max UDP datagram + overhead
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		conn.WriteToUDP(buf[:n], raddr)
	}
}

func fetchAllocMB(pprofPort int) float64 {
	url := fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/heap?debug=1", pprofPort)
	var body []byte
	for i := 0; i < 3; i++ {
		resp, err := http.Get(url)
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		body, _ = io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		break
	}
	if body == nil {
		return 0
	}
	// First line: "heap profile: N: M [X: Y] @ heap/RATE"
	line := string(body)
	if nl := strings.IndexByte(line, '\n'); nl > 0 {
		line = line[:nl]
	}
	j := strings.LastIndex(line, "[")
	k := strings.LastIndex(line, "]")
	if j >= 0 && k > j {
		parts := strings.Split(line[j+1:k], ": ")
		if len(parts) == 2 {
			bytes, _ := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
			return math.Round(bytes/1024/1024*100) / 100
		}
	}
	return 0
}

func collectPprof(port int, res *result) {
	client := &http.Client{Timeout: 5 * time.Second}
	base := fmt.Sprintf("http://127.0.0.1:%d/debug/pprof", port)
	td := ccTempDir()
	pid := os.Getpid()

	for _, kind := range []string{"allocs", "heap"} {
		resp, err := client.Get(base + "/" + kind)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}
		profFile := fmt.Sprintf("%s/bench-pprof-%d-%s.prof", td, pid, kind)
		os.WriteFile(profFile, data, 0644)

		svgFile := fmt.Sprintf("%s/bench-pprof-%d-%s.svg", td, pid, kind)
		if svg, err := generateTightSVG(profFile); err == nil {
			os.WriteFile(svgFile, svg, 0644)
			if kind == "allocs" {
				res.PprofAllocsSVG = svgFile
			} else {
				res.PprofHeapSVG = svgFile
			}
		}

		sites := analyzePprof(profFile, kind)
		if kind == "allocs" {
			res.PprofAllocs = sites
		} else {
			res.PprofHeap = sites
		}
	}
}

func analyzePprof(profilePath, kind string) []pprofSite {
	out, err := exec.Command("go", "tool", "pprof", "-top", "-nodecount=20", profilePath).Output()
	if err != nil {
		return nil
	}
	sites := parsePprofTop(string(out))
	return sites
}

func parsePprofTop(output string) []pprofSite {
	var sites []pprofSite
	lines := strings.Split(output, "\n")
	inTable := false
	for _, line := range lines {
		if strings.HasPrefix(line, "Showing nodes accounting") {
			inTable = true
			continue
		}
		if !inTable || line == "" {
			continue
		}
		if line[0] != 0x20 && line[0] != 0x09 {
			continue
		}
		if strings.HasPrefix(line, "      flat  flat%") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		var s pprofSite
		s.Flat, _ = parseSize(fields[0])
		s.FlatPct, _ = strconv.ParseFloat(strings.TrimSuffix(fields[1], "%"), 64)
		s.SumPct, _ = strconv.ParseFloat(strings.TrimSuffix(fields[2], "%"), 64)
		s.Cum, _ = parseSize(fields[3])
		s.CumPct, _ = strconv.ParseFloat(strings.TrimSuffix(fields[4], "%"), 64)
		if len(fields) >= 6 {
			s.Function = fields[5]
		}
		sites = append(sites, s)
	}
	return sites
}

func generatePprofFlameSVG(profilePath string) ([]byte, error) {
	// Use pprof directly — includes SVGPan scripts for zoom/pan
	cmd := exec.Command("go", "tool", "pprof", "-svg", "-nodecount=50", profilePath)
	return cmd.Output()
}

// generateTightSVG generates a compact SVG with viewBox via graphviz for inline display.
func generateTightSVG(profilePath string) ([]byte, error) {
	dotOut, err := exec.Command("go", "tool", "pprof", "-dot", "-nodecount=50", profilePath).Output()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command("dot", "-Tsvg", "-Gmargin=0")
	cmd.Stdin = strings.NewReader(string(dotOut))
	return cmd.Output()
}

func parseSize(s string) (float64, error) {
	s = strings.TrimSpace(s)
	for _, unit := range []string{"MB", "kB", "GB", "B"} {
		if strings.HasSuffix(s, unit) {
			v, err := strconv.ParseFloat(strings.TrimSuffix(s, unit), 64)
			if err != nil {
				return 0, err
			}
			switch unit {
			case "GB":
				return v * 1024, nil
			case "kB":
				return v / 1024, nil
			case "B":
				return v / 1024 / 1024, nil
			}
			return v, nil
		}
	}
	return strconv.ParseFloat(s, 64)
}

// fetchCPUFromProfile collects a pprof CPU profile for secs seconds, populates
// res.PprofCPU and res.PprofCPUSVG*, and returns the CPU%.
// Returns -1 on error (to distinguish "failed" from genuinely 0% CPU).
func fetchCPUFromProfile(pprofPort int, secs int, res *result) float64 {
	// Wait for pprof server to be ready.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", pprofPort), 500*time.Millisecond); err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	client := &http.Client{Timeout: time.Duration(secs+10) * time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/debug/pprof/profile?seconds=%d", pprofPort, secs)
	resp, err := client.Get(url)
	if err != nil {
		return -1
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || len(data) == 0 {
		return -1
	}

	profFile := filepath.Join(ccTempDir(), fmt.Sprintf("bench-cpu-%d.prof", os.Getpid()))
	os.WriteFile(profFile, data, 0644)

	if svg, err := generateTightSVG(profFile); err == nil {
		svgFile := filepath.Join(ccTempDir(), fmt.Sprintf("bench-cpu-%d.svg", os.Getpid()))
		os.WriteFile(svgFile, svg, 0644)
		res.PprofCPUSVG = svgFile
	}
	if svg, err := generatePprofFlameSVG(profFile); err == nil {
		rawFile := filepath.Join(ccTempDir(), fmt.Sprintf("bench-cpu-%d-raw.svg", os.Getpid()))
		os.WriteFile(rawFile, svg, 0644)
		res.PprofCPUSVGRaw = rawFile
	}

	out, err := exec.Command("go", "tool", "pprof", "-top", "-nodecount=0", profFile).Output()
	os.Remove(profFile)
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "Total samples") {
			continue
		}
		if i := strings.Index(line, "("); i >= 0 {
			if j := strings.Index(line[i:], "%"); j >= 0 {
				pct, _ := strconv.ParseFloat(strings.TrimSpace(line[i+1:i+j]), 64)
				return math.Round(pct*10) / 10
			}
		}
		return 0
	}
	return -1
}

func parseConnErrors(out string) int {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "CONN_ERRORS ") {
			n, _ := strconv.Atoi(strings.TrimSpace(line[12:]))
			return n
		}
	}
	return 0
}
