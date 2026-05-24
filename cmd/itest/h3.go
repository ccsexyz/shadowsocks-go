package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/urfave/cli/v2"
)

var h3Command = &cli.Command{
	Name:  "h3",
	Usage: "HTTP/3 connectivity test",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "url", Required: true, Usage: "target URL, e.g. https://www.example.com"},
		&cli.StringFlag{Name: "proxy", Usage: "UDP proxy address ip:port"},
		&cli.BoolFlag{Name: "insecure", Aliases: []string{"k"}, Usage: "skip TLS certificate verification"},
		&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}, Usage: "print response headers and timing"},
	},
	Action: func(c *cli.Context) error {
		u, err := parseH3URL(c.String("url"))
		if err != nil {
			return fmt.Errorf("invalid URL: %w", err)
		}

		if !c.Bool("verbose") {
			log.SetOutput(io.Discard)
		}

		tlsCfg := &tls.Config{
			ServerName:         u.host,
			InsecureSkipVerify: c.Bool("insecure"),
			NextProtos:         []string{"h3"},
		}
		quicCfg := &quic.Config{}

		var dial func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error)

		if proxyAddr := c.String("proxy"); proxyAddr != "" {
			proxyUDPAddr, err := net.ResolveUDPAddr("udp", proxyAddr)
			if err != nil {
				return fmt.Errorf("resolve proxy %s: %w", proxyAddr, err)
			}
			dial = func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				log.Printf("QUIC: dial %s via proxy %s (SNI=%s)", addr, proxyAddr, tlsCfg.ServerName)
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

		tr := &http3.Transport{TLSClientConfig: tlsCfg, QUICConfig: quicCfg, Dial: dial}
		defer tr.Close()

		client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
		start := time.Now()
		resp, err := client.Get(c.String("url"))
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		elapsed := time.Since(start)
		n, _ := io.Copy(io.Discard, resp.Body)

		if c.Bool("verbose") {
			fmt.Printf("HTTP/3 %d %s\n", resp.StatusCode, resp.Status)
			for k, vs := range resp.Header {
				for _, v := range vs {
					fmt.Printf("%s: %s\n", k, v)
				}
			}
			fmt.Println()
		}
		fmt.Printf("status: %d  bytes: %d  time: %v\n", resp.StatusCode, n, elapsed.Round(time.Millisecond))
		return nil
	},
}

type h3URL struct {
	addr string
	host string
}

func parseH3URL(raw string) (*h3URL, error) {
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
	return &h3URL{addr: net.JoinHostPort(host, port), host: host}, nil
}
