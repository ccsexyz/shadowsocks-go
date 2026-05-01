// Command h3test is a minimal HTTP/3 client for testing UDP forwarding chains.
// It can override the UDP destination so QUIC packets go through a proxy
// (like udpforward) while preserving the correct TLS SNI.
//
// Usage:
//
//	h3test -url https://www.example.com -proxy 127.0.0.1:1053
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var (
	targetURL = flag.String("url", "", "target URL, e.g. https://www.example.com")
	proxyAddr = flag.String("proxy", "", "UDP proxy address ip:port, e.g. udpforward listen address")
	insecure  = flag.Bool("k", false, "skip TLS certificate verification")
	verbose   = flag.Bool("v", false, "verbose: print response headers and timing")
)

func main() {
	flag.Parse()
	if *targetURL == "" {
		fmt.Fprintf(os.Stderr, "usage: h3test -url https://host[:port] [-proxy ip:port] [-k] [-v]\n")
		os.Exit(1)
	}

	u, err := parseURL(*targetURL)
	if err != nil {
		log.Fatalf("invalid URL: %v", err)
	}

	if !*verbose {
		log.SetOutput(io.Discard)
	}

	tlsCfg := &tls.Config{
		ServerName:         u.host,
		InsecureSkipVerify: *insecure,
		NextProtos:         []string{"h3"},
	}
	quicCfg := &quic.Config{}

	var dial func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)

	if *proxyAddr != "" {
		proxyUDPAddr, err := net.ResolveUDPAddr("udp", *proxyAddr)
		if err != nil {
			log.Fatalf("resolve proxy %s: %v", *proxyAddr, err)
		}
		dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			log.Printf("QUIC: dial %s via proxy %s (SNI=%s)", addr, *proxyAddr, tlsCfg.ServerName)

			udpConn, err := net.ListenUDP("udp", nil)
			if err != nil {
				return nil, err
			}

			conn, err := quic.Dial(ctx, udpConn, proxyUDPAddr, tlsCfg, cfg)
			if err != nil {
				udpConn.Close()
				return nil, err
			}
			return conn, nil
		}
	} else {
		log.Printf("QUIC: dial %s (direct)", u.addr)
	}

	tr := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      quicCfg,
		Dial:            dial,
	}
	defer tr.Close()

	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	start := time.Now()
	resp, err := client.Get(*targetURL)
	if err != nil {
		log.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	elapsed := time.Since(start)
	n, _ := io.Copy(io.Discard, resp.Body)

	if *verbose {
		fmt.Printf("HTTP/3 %d %s\n", resp.StatusCode, resp.Status)
		for k, vs := range resp.Header {
			for _, v := range vs {
				fmt.Printf("%s: %s\n", k, v)
			}
		}
		fmt.Println()
	}
	fmt.Printf("status: %d  bytes: %d  time: %v\n", resp.StatusCode, n, elapsed.Round(time.Millisecond))
}

type urlInfo struct {
	addr string // host:port
	host string // host only (SNI)
}

func parseURL(raw string) (*urlInfo, error) {
	s := raw
	if len(s) > 8 && s[:8] == "https://" {
		s = s[8:]
	} else if len(s) > 7 && s[:7] == "http://" {
		s = s[7:]
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host = s
		port = "443"
	}
	return &urlInfo{addr: net.JoinHostPort(host, port), host: host}, nil
}
