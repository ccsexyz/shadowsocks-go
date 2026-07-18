package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/time/rate"
)

var loadCommand = &cli.Command{
	Name:  "load",
	Usage: "payload load generator through SOCKS5 proxy",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "socks", Value: "127.0.0.1:1080", Usage: "SOCKS5 proxy address"},
		&cli.StringFlag{Name: "target", Required: true, Usage: "target host:port"},
		&cli.IntFlag{Name: "concurrency", Aliases: []string{"c"}, Value: 100, Usage: "concurrent connections"},
		&cli.DurationFlag{Name: "duration", Aliases: []string{"d"}, Value: 20 * time.Second, Usage: "test duration"},
		&cli.IntFlag{Name: "size", Value: 512, Usage: "payload size in bytes"},
		&cli.BoolFlag{Name: "latency", Usage: "measure and report latency percentiles"},
		&cli.Float64Flag{Name: "bw", Value: 0, Usage: "bandwidth limit in Mbps (0 = unlimited)"},
	},
	Action: func(c *cli.Context) error {
		ls := &latencySamples{}
		return runLoad(
			c.String("socks"), c.String("target"),
			c.Int("concurrency"), c.Duration("duration"), c.Int("size"),
			c.Bool("latency"), c.Float64("bw"), ls,
		)
	},
}

type latencySamples struct {
	firstByte []time.Duration
	rtt       []time.Duration
	mu        sync.Mutex
}

func (l *latencySamples) addFB(d time.Duration) {
	l.mu.Lock()
	l.firstByte = append(l.firstByte, d)
	l.mu.Unlock()
}
func (l *latencySamples) addRTT(d time.Duration) {
	l.mu.Lock()
	l.rtt = append(l.rtt, d)
	l.mu.Unlock()
}
func (l *latencySamples) percentiles() (fbP50, fbP95, fbP99, rttP50, rttP95, rttP99 float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.firstByte) > 0 {
		s := make([]float64, len(l.firstByte))
		for i, d := range l.firstByte {
			s[i] = float64(d.Microseconds())
		}
		slices.Sort(s)
		fbP50 = s[len(s)*50/100]
		fbP95 = s[len(s)*95/100]
		fbP99 = s[len(s)*99/100]
	}
	if len(l.rtt) > 0 {
		s := make([]float64, len(l.rtt))
		for i, d := range l.rtt {
			s[i] = float64(d.Microseconds())
		}
		slices.Sort(s)
		rttP50 = s[len(s)*50/100]
		rttP95 = s[len(s)*95/100]
		rttP99 = s[len(s)*99/100]
	}
	return
}

func runLoad(socksAddr, targetAddr string, concurrency int, dur time.Duration, payloadSize int, latency bool, bwMbps float64, ls *latencySamples) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() { <-sigCh; cancel() }()

	var limiter *rate.Limiter
	if bwMbps > 0 {
		limitBytes := int(bwMbps * 1_000_000 / 8)
		burst := limitBytes / 10
		if burst < payloadSize {
			burst = payloadSize
		}
		limiter = rate.NewLimiter(rate.Limit(limitBytes), burst)
	}

	var wg sync.WaitGroup
	var totalBytes atomic.Int64
	var errors atomic.Int64
	start := time.Now()
	durSecs := dur.Seconds()
	deadline := start.Add(dur)

	payload := make([]byte, payloadSize)
	rand.Read(payload)

	for i := 0; i < concurrency; i++ {
		if time.Now().After(deadline) {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := dialSocksBench(socksAddr, targetAddr)
			if err != nil {
				errors.Add(1)
				return
			}
			defer conn.Close()

			buf := make([]byte, payloadSize)
			// Per-operation deadline: a stalled read must not block
			// the goroutine forever.  With a 15s window a single
			// slow/lost connection will fail gracefully rather than
			// hanging the whole benchmark via wg.Wait().
			const opTimeout = 15 * time.Second
			for time.Now().Before(deadline) {
				if limiter != nil {
					limiter.WaitN(ctx, payloadSize)
				}
				conn.SetDeadline(time.Now().Add(opTimeout))
				if _, err := conn.Write(payload); err != nil {
					errors.Add(1)
					return
				}
				t0 := time.Now()
				conn.SetDeadline(time.Now().Add(opTimeout))
				if _, err := io.ReadFull(conn, buf); err != nil {
					errors.Add(1)
					return
				}
				if latency {
					ls.addFB(time.Since(t0))
					ls.addRTT(time.Since(t0))
				}
				_ = t0
				totalBytes.Add(int64(payloadSize))
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start).Seconds()
	total := totalBytes.Load()
	errs := errors.Load()
	// Use the configured duration as denominator so early connection failures
	// don't inflate throughput numbers.
	tput := float64(total) / durSecs / 1e6

	fmt.Printf("Throughput: %.1f MB/s\n", tput)
	fmt.Printf("CONN_ERRORS %d\n", errs)
	fmt.Printf("CONN_TOTAL %d\n", concurrency)
	fmt.Printf("Total: %.1f MB in %.1fs (configured: %.0fs)\n", float64(total)/1e6, elapsed, durSecs)
	if latency {
		fbP50, fbP95, fbP99, rttP50, rttP95, rttP99 := ls.percentiles()
		fmt.Printf("LATENCY fb_p50=%.3fus fb_p95=%.3fus fb_p99=%.3fus rtt_p50=%.3fus rtt_p95=%.3fus rtt_p99=%.3fus\n",
			fbP50, fbP95, fbP99, rttP50, rttP95, rttP99)
	}
	return nil
}

func dialSocksBench(socksAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	// Set a deadline so a stalled SOCKS handshake doesn't block
	// the goroutine forever. The proxy should respond within seconds.
	c.SetDeadline(time.Now().Add(15 * time.Second))
	c.Write([]byte{5, 1, 0})
	buf := make([]byte, 512)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		c.Close()
		return nil, err
	}
	host, portStr, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(portStr)
	ip := net.ParseIP(host)
	req := []byte{5, 1, 0}
	if ip != nil && ip.To4() != nil {
		req = append(req, 1)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))
	c.Write(req)
	if _, err := io.ReadFull(c, buf[:10]); err != nil {
		c.Close()
		return nil, err
	}
	if buf[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("SOCKS5 connect failed: code %d", buf[1])
	}
	return c, nil
}
