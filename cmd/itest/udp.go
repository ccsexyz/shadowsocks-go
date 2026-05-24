package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/urfave/cli/v2"
)

var udpCommand = &cli.Command{
	Name:  "udp",
	Usage: "UDP echo server or benchmark client",
	Flags: []cli.Flag{
		&cli.BoolFlag{Name: "server", Aliases: []string{"s"}, Usage: "run as echo server"},
		&cli.StringFlag{Name: "addr", Aliases: []string{"l"}, Value: ":5201", Usage: "listen address (server) / target address (client)"},
		&cli.IntFlag{Name: "rate", Aliases: []string{"b"}, Value: 5, Usage: "send rate in Mbps (client mode)"},
		&cli.DurationFlag{Name: "duration", Aliases: []string{"t"}, Value: 8 * time.Second, Usage: "test duration (client mode)"},
		&cli.IntFlag{Name: "size", Value: 512, Usage: "payload size in bytes, min 12 (client mode)"},
	},
	Action: func(c *cli.Context) error {
		if c.Bool("server") {
			return runUDPEchoServer(c.String("addr"))
		}
		return runUDPBenchClient(c.String("addr"), c.Int("rate"), c.Int("size"), c.Duration("duration"))
	},
}

func runUDPEchoServer(addr string) error {
	uaddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		return err
	}
	defer conn.Close()
	fmt.Printf("UDP echo on %s\n", conn.LocalAddr())

	buf := make([]byte, 2048)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		conn.WriteToUDP(buf[:n], raddr)
	}
}

func runUDPBenchClient(target string, rateMbps, packetSize int, dur time.Duration) error {
	if packetSize < 12 {
		packetSize = 12
	}
	targetBps := rateMbps * 1_000_000
	packetsPerSec := targetBps / (packetSize * 8)
	if packetsPerSec < 1 {
		packetsPerSec = 1
	}
	interval := time.Second / time.Duration(packetsPerSec)

	raddr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Printf("UDP bench: %s  %d Mbps  %dB payload  %d pps  %v\n",
		target, rateMbps, packetSize, packetsPerSec, dur)

	start := time.Now()
	deadline := start.Add(dur)
	var sent, received, lost, corrupted int64
	var minRTT, maxRTT, totalRTT time.Duration
	minRTT = 1 << 62

	buf := make([]byte, 2048)
	var seq uint32
	sendNext := start

	for time.Now().Before(deadline) {
		now := time.Now()
		binary.BigEndian.PutUint32(buf[0:4], seq)
		binary.BigEndian.PutUint64(buf[4:12], uint64(now.UnixNano()))
		for i := 12; i < packetSize; i++ {
			buf[i] = byte((seq + uint32(i)) % 251)
		}

		sendNext = sendNext.Add(interval)
		if sleepFor := time.Until(sendNext); sleepFor > 0 {
			time.Sleep(sleepFor)
		}

		conn.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := conn.Write(buf[:packetSize]); err != nil {
			log.Printf("write error: %v", err)
			break
		}
		sent++

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

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	for {
		_, err := conn.Read(buf)
		if err != nil {
			break
		}
		received++
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
	return nil
}
