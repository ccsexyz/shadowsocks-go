package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

var (
	serverMode = flag.Bool("s", false, "server mode: echo received packets back to sender")
	listenAddr = flag.String("l", ":5201", "listen address (server) / target address (client)")
	rate       = flag.Int("b", 5, "send rate in Mbps")
	duration   = flag.Duration("t", 8*time.Second, "test duration")
	payload    = flag.Int("size", 512, "payload size in bytes (min 12)")
)

func main() {
	flag.Parse()
	if *serverMode {
		runServer()
	} else {
		runClient()
	}
}

func runServer() {
	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Printf("server: listening on UDP %s (echo mode)\n", conn.LocalAddr())

	buf := make([]byte, 2048)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		// Echo the entire packet back — the client verifies it.
		conn.WriteToUDP(buf[:n], raddr)
	}
}

func runClient() {
	raddr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	packetSize := *payload
	if packetSize < 12 {
		packetSize = 12
	}
	targetBps := *rate * 1_000_000
	packetsPerSec := targetBps / (packetSize * 8)
	if packetsPerSec < 1 {
		packetsPerSec = 1
	}
	interval := time.Second / time.Duration(packetsPerSec)

	fmt.Printf("client: %s  %d Mbps  %dB payload  %d pps  %v\n",
		*listenAddr, *rate, packetSize, packetsPerSec, *duration)

	start := time.Now()
	deadline := start.Add(*duration)

	var sent, received int64
	var lost, corrupted int64
	var minRTT, maxRTT, totalRTT time.Duration
	minRTT = 1 << 62

	buf := make([]byte, 2048)
	var seq uint32

	sendNext := start
	for time.Now().Before(deadline) {
		// Build packet: 4-byte sequence + 8-byte timestamp + payload pattern
		now := time.Now()
		binary.BigEndian.PutUint32(buf[0:4], seq)
		binary.BigEndian.PutUint64(buf[4:12], uint64(now.UnixNano()))
		for i := 12; i < packetSize; i++ {
			buf[i] = byte((seq + uint32(i)) % 251)
		}

		sendNext = sendNext.Add(interval)
		sleepFor := time.Until(sendNext)
		if sleepFor > 0 {
			time.Sleep(sleepFor)
		}

		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(buf[:packetSize]); err != nil {
			log.Printf("write error: %v", err)
			break
		}
		sent++

		// Try to read a response (non-blocking)
		conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
		n, err := conn.Read(buf)
		if err == nil {
			received++
			if n >= 12 {
				rseq := binary.BigEndian.Uint32(buf[0:4])
				rts := int64(binary.BigEndian.Uint64(buf[4:12]))
				rtt := time.Since(time.Unix(0, rts))
				if rtt > 0 && rtt < time.Hour {
					totalRTT += rtt
					if rtt < minRTT {
						minRTT = rtt
					}
					if rtt > maxRTT {
						maxRTT = rtt
					}
				}
				// Verify payload pattern
				for i := 12; i < n; i++ {
					if buf[i] != byte((rseq+uint32(i))%251) {
						corrupted++
						break
					}
				}
			}
		}

		seq++
	}

	// Drain remaining responses
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		received++
		_ = n
	}

	lost = sent - received
	elapsed := time.Since(start).Seconds()

	fmt.Println()
	fmt.Printf("=== Results ===\n")
	fmt.Printf("Duration:     %.1fs\n", elapsed)
	fmt.Printf("Sent:         %d packets\n", sent)
	fmt.Printf("Received:     %d packets\n", received)
	fmt.Printf("Lost:         %d packets (%.1f%%)\n", lost, float64(lost)/float64(sent)*100)
	fmt.Printf("Corrupted:    %d packets\n", corrupted)
	if received > 0 {
		fmt.Printf("Avg RTT:      %v\n", totalRTT/time.Duration(received))
		fmt.Printf("Min RTT:      %v\n", minRTT)
		fmt.Printf("Max RTT:      %v\n", maxRTT)
	}
	sentMbps := float64(sent*int64(packetSize)*8) / elapsed / 1e6
	recvMbps := float64(received*int64(packetSize)*8) / elapsed / 1e6
	fmt.Printf("Send rate:    %.2f Mbps\n", sentMbps)
	fmt.Printf("Recv rate:    %.2f Mbps\n", recvMbps)
}
