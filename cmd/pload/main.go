// Command pload is a TCP load generator that connects through a SOCKS5 proxy,
// sends data, reads echo, and reports throughput. Used for performance profiling.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

var (
	socksAddr   = flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy address")
	targetAddr  = flag.String("target", "", "target host:port (required)")
	concurrency = flag.Int("c", 100, "concurrent connections")
	duration    = flag.Duration("d", 20*time.Second, "test duration")
	payloadSize = flag.Int("size", 512, "payload size in bytes")
)

func main() {
	flag.Parse()
	if *targetAddr == "" {
		fmt.Fprintf(os.Stderr, "usage: pload -socks <addr> -target <host:port> [-c 100] [-d 20s] [-size 512]\n")
		os.Exit(1)
	}

	targetHost, targetPortStr, err := net.SplitHostPort(*targetAddr)
	if err != nil {
		log.Fatal("invalid target:", err)
	}
	targetPort, err := strconv.Atoi(targetPortStr)
	if err != nil {
		log.Fatal("invalid target port:", err)
	}

	log.Printf("pload: SOCKS5=%s target=%s concurrency=%d duration=%v size=%d",
		*socksAddr, *targetAddr, *concurrency, *duration, *payloadSize)

	var totalBytes atomic.Int64
	var totalConns atomic.Int64
	var totalErrors atomic.Int64
	var wg sync.WaitGroup

	deadline := time.Now().Add(*duration)
	payload := make([]byte, *payloadSize)
	rand.Read(payload)

	// Print progress every second
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				elapsed := time.Since(deadline.Add(-*duration)).Seconds()
				mb := float64(totalBytes.Load()) / elapsed / 1024 / 1024
				cps := float64(totalConns.Load()) / elapsed
				log.Printf("  %.1f MB/s  %.0f conns/s  %d errors", mb, cps, totalErrors.Load())
			}
		}
	}()

	// Handle SIGINT gracefully
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	ctxDone := make(chan struct{})
	go func() {
		select {
		case <-sigCh:
			log.Println("interrupted, stopping...")
		case <-time.After(*duration):
		}
		close(ctxDone)
	}()

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, *payloadSize)

			// Establish persistent SOCKS5 connection
			conn, err := net.DialTimeout("tcp", *socksAddr, 5*time.Second)
			if err != nil {
				totalErrors.Add(1)
				return
			}
			defer conn.Close()

			if err := socks5Handshake(conn, targetHost, targetPort); err != nil {
				totalErrors.Add(1)
				return
			}
			totalConns.Add(1)

			// Exchange data on persistent connection
			for {
				select {
				case <-ctxDone:
					return
				default:
				}

				if _, err := conn.Write(payload); err != nil {
					totalErrors.Add(1)
					return
				}

				if _, err := io.ReadFull(conn, buf); err != nil {
					totalErrors.Add(1)
					return
				}
				totalBytes.Add(int64(*payloadSize * 2))
			}
		}()
	}

	wg.Wait()
	close(done)

	elapsed := time.Since(deadline.Add(-*duration)).Seconds()
	mb := float64(totalBytes.Load()) / elapsed / 1024 / 1024
	cps := float64(totalConns.Load()) / elapsed

	fmt.Println()
	fmt.Printf("=== Results ===\n")
	fmt.Printf("Duration:     %.1fs\n", elapsed)
	fmt.Printf("Throughput:   %.1f MB/s\n", mb)
	fmt.Printf("Connections:  %.0f conns/s (%d total)\n", cps, totalConns.Load())
	fmt.Printf("Errors:       %d\n", totalErrors.Load())
}

func socks5Handshake(conn net.Conn, host string, port int) error {
	// Method negotiation
	conn.Write([]byte{5, 1, 0})
	buf := make([]byte, 512)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return err
	}
	if buf[0] != 5 || buf[1] != 0 {
		return fmt.Errorf("SOCKS5 method rejected: %x", buf[:2])
	}

	// Connect request
	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))
	conn.Write(req)

	if _, err := io.ReadFull(conn, buf[:10]); err != nil {
		return err
	}
	if buf[1] != 0 {
		return fmt.Errorf("SOCKS5 connect failed: rep=%d", buf[1])
	}
	return nil
}
