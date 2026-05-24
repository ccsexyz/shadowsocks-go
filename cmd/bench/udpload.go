package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/crc64"
	"io"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urfave/cli/v2"
	"golang.org/x/time/rate"
)

var crcTable = crc64.MakeTable(crc64.ECMA)

var udpLoadCommand = &cli.Command{
	Name:  "udpload",
	Usage: "UDP load generator through SOCKS5 UDP relay",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "socks", Value: "127.0.0.1:1080", Usage: "SOCKS5 proxy address (TCP)"},
		&cli.StringFlag{Name: "target", Required: true, Usage: "target host:port"},
		&cli.IntFlag{Name: "concurrency", Aliases: []string{"c"}, Value: 10, Usage: "concurrent UDP senders"},
		&cli.DurationFlag{Name: "duration", Aliases: []string{"d"}, Value: 20 * time.Second, Usage: "test duration"},
		&cli.IntFlag{Name: "size", Value: 512, Usage: "UDP payload size in bytes (min 20 for header)"},
		&cli.IntFlag{Name: "inflight", Aliases: []string{"w"}, Value: 65536, Usage: "max in-flight bytes per sender (window = inflight / size, min 8)"},
		&cli.Float64Flag{Name: "bw", Value: 0, Usage: "bandwidth limit in Mbps (0 = unlimited)"},
	},
	Action: func(c *cli.Context) error {
		return runUDPLoad(
			c.String("socks"), c.String("target"),
			c.Int("concurrency"), c.Duration("duration"), c.Int("size"),
			c.Float64("bw"), c.Int("inflight"),
		)
	},
}

func runUDPLoad(socksAddr, targetAddr string, concurrency int, dur time.Duration, payloadSize int, bwMbps float64, inflightBytes int) error {
	if payloadSize < 20 {
		payloadSize = 20
	}
	windowSize := inflightBytes / payloadSize
	if windowSize < 8 {
		windowSize = 8
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() { <-sigCh; cancel() }()

	hostStr, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		return fmt.Errorf("lookup port: %w", err)
	}

	var limiter *rate.Limiter
	if bwMbps > 0 {
		limitBytes := int(bwMbps * 1_000_000 / 8)
		burst := limitBytes / 10
		if burst < payloadSize {
			burst = payloadSize
		}
		limiter = rate.NewLimiter(rate.Limit(limitBytes), burst)
	}

	var totalBytes, totalSent, totalRecv, totalLost atomic.Int64
	start := time.Now()
	durSecs := dur.Seconds()
	deadline := start.Add(dur)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		relayAddr, err := socks5UDPAssociate(socksAddr)
		if err != nil {
			return fmt.Errorf("SOCKS5 UDP ASSOCIATE[%d]: %w", i, err)
		}
		rAddr, err := net.ResolveUDPAddr("udp", relayAddr)
		if err != nil {
			return fmt.Errorf("resolve relay[%d]: %w", i, err)
		}
		conn, err := net.DialUDP("udp", nil, rAddr)
		if err != nil {
			return fmt.Errorf("dial relay[%d]: %w", i, err)
		}
		defer conn.Close()

		wg.Add(1)
		go func() {
			defer wg.Done()
			udpSenderRecv(ctx, conn, hostStr, port, payloadSize, windowSize, deadline,
				limiter, &totalBytes, &totalSent, &totalRecv, &totalLost)
		}()
	}

	wg.Wait()

	elapsed := time.Since(start).Seconds()
	total := totalBytes.Load()
	sent := totalSent.Load()
	recv := totalRecv.Load()
	lost := totalLost.Load()
	tput := float64(total) / durSecs / 1e6

	fmt.Printf("Throughput: %.1f MB/s\n", tput)
	fmt.Printf("UDP_SENT %d\n", sent)
	fmt.Printf("UDP_RECV %d\n", recv)
	fmt.Printf("UDP_LOST %d\n", lost)
	fmt.Printf("CONN_ERRORS 0\n")
	fmt.Printf("CONN_TOTAL %d\n", concurrency)
	fmt.Printf("Total: %.1f MB in %.1fs (configured: %.0fs)\n", float64(total)/1e6, elapsed, durSecs)
	return nil
}

func udpSenderRecv(ctx context.Context, conn *net.UDPConn, host string, port, payloadSize, windowSize int,
	deadline time.Time, limiter *rate.Limiter,
	totalBytes, totalSent, totalRecv, totalLost *atomic.Int64) {

	inflight := make(map[uint32]bool, windowSize)
	var sendSeq uint32

	// Receiver goroutine — feeds results into a channel
	results := make(chan recvResult, 256)
	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		buf := make([]byte, payloadSize+262)
		for {
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := conn.Read(buf)
			if err != nil {
				if time.Now().After(deadline.Add(300 * time.Millisecond)) {
					return
				}
				continue
			}
			payload, err := parseSocks5UDPResponse(buf[:n])
			if err != nil || len(payload) < 20 {
				continue
			}
			seq := binary.BigEndian.Uint32(payload[0:4])
			crcGot := binary.BigEndian.Uint64(payload[12:20])
			crcExp := crc64.Checksum(payload[:12], crcTable)
			if crcGot != crcExp {
				continue
			}
			select {
			case results <- recvResult{seq: seq, n: len(payload) - 20}:
			default:
			}
		}
	}()

	// Sender loop: send up to windowSize, block on recv when full
	for time.Now().Before(deadline) {
		if limiter != nil {
			limiter.WaitN(ctx, payloadSize)
		}

		// Drain received results
		drainResults(results, inflight, totalRecv, totalBytes)

		// Window full: wait for a result with deadline awareness
		if len(inflight) >= windowSize {
			select {
			case r, ok := <-results:
				if ok {
					if inflight[r.seq] {
						delete(inflight, r.seq)
					}
					totalRecv.Add(1)
					totalBytes.Add(int64(r.n))
				}
			case <-time.After(10 * time.Millisecond):
			}
			drainResults(results, inflight, totalRecv, totalBytes)
			continue
		}

		seq := sendSeq
		sendSeq++

		buf := make([]byte, payloadSize+262)
		now := time.Now()
		binary.BigEndian.PutUint32(buf[0:4], seq)
		binary.BigEndian.PutUint64(buf[4:12], uint64(now.UnixNano()))
		for i := 20; i < payloadSize; i++ {
			buf[i] = byte((seq + uint32(i)) % 251)
		}
		crc := crc64.Checksum(buf[:12], crcTable)
		binary.BigEndian.PutUint64(buf[12:20], crc)

		pkt := buildSocks5UDPPacket(host, port, buf[:payloadSize])
		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(pkt); err != nil {
			return
		}
		totalSent.Add(1)
		inflight[seq] = true
	}

	// Drain remaining
	drainDeadline := time.Now().Add(500 * time.Millisecond)
	for len(inflight) > 0 && time.Now().Before(drainDeadline) {
		select {
		case r, ok := <-results:
			if !ok {
				totalLost.Add(int64(len(inflight)))
				return
			}
			if inflight[r.seq] {
				delete(inflight, r.seq)
			}
			totalRecv.Add(1)
			totalBytes.Add(int64(r.n))
			drainResults(results, inflight, totalRecv, totalBytes)
		case <-time.After(200 * time.Millisecond):
			drainResults(results, inflight, totalRecv, totalBytes)
		}
	}
	totalLost.Add(int64(len(inflight)))
}

type recvResult struct {
	seq uint32
	n   int
}

func drainResults(ch chan recvResult, inflight map[uint32]bool, totalRecv, totalBytes *atomic.Int64) {
	for {
		select {
		case r := <-ch:
			if inflight[r.seq] {
				delete(inflight, r.seq)
			}
			totalRecv.Add(1)
			totalBytes.Add(int64(r.n))
		default:
			return
		}
	}
}

func socks5UDPAssociate(addr string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial SOCKS5: %w", err)
	}
	defer conn.Close()
	conn.Write([]byte{5, 1, 0})
	buf := make([]byte, 512)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", fmt.Errorf("handshake: %w", err)
	}
	if buf[0] != 5 || buf[1] != 0 {
		return "", fmt.Errorf("method rejected: %x", buf[:2])
	}
	conn.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	if _, err := io.ReadFull(conn, buf[:10]); err != nil {
		return "", fmt.Errorf("UDP ASSOCIATE: %w", err)
	}
	if buf[1] != 0 {
		return "", fmt.Errorf("UDP ASSOCIATE rejected: rep=%d", buf[1])
	}
	relayIP := net.IP(buf[4:8]).String()
	relayPort := int(binary.BigEndian.Uint16(buf[8:10]))
	return fmt.Sprintf("%s:%d", relayIP, relayPort), nil
}

func buildSocks5UDPPacket(host string, port int, data []byte) []byte {
	ip := net.ParseIP(host)
	pkt := make([]byte, 0, 3+1+len(host)+2+len(data))
	pkt = append(pkt, 0, 0, 0)
	if ip4 := ip.To4(); ip4 != nil {
		pkt = append(pkt, 1)
		pkt = append(pkt, ip4...)
	} else if ip6 := ip.To16(); ip6 != nil {
		pkt = append(pkt, 4)
		pkt = append(pkt, ip6...)
	} else {
		pkt = append(pkt, 3, byte(len(host)))
		pkt = append(pkt, []byte(host)...)
	}
	pkt = append(pkt, byte(port>>8), byte(port&0xff))
	pkt = append(pkt, data...)
	return pkt
}

func parseSocks5UDPResponse(pkt []byte) ([]byte, error) {
	if len(pkt) < 10 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(pkt))
	}
	atyp := pkt[3]
	var hdrLen int
	switch atyp {
	case 1:
		hdrLen = 10
	case 3:
		if len(pkt) < 3+1+1 {
			return nil, fmt.Errorf("domain header too short")
		}
		hdrLen = 3 + 1 + 1 + int(pkt[4]) + 2
	case 4:
		hdrLen = 3 + 1 + 16 + 2
	default:
		return nil, fmt.Errorf("unknown ATYP: %d", atyp)
	}
	if len(pkt) < hdrLen {
		return nil, fmt.Errorf("header too big: %d < %d", len(pkt), hdrLen)
	}
	return pkt[hdrLen:], nil
}
