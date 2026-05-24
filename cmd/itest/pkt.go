package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/urfave/cli/v2"
	mrand "math/rand/v2"
)

var pktCommand = &cli.Command{
	Name:  "pkt",
	Usage: "packet-level integrity stress test through a SOCKS5 proxy or direct connection",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "target", Required: true, Usage: "target address (host:port)"},
		&cli.StringFlag{Name: "socks", Usage: "SOCKS5 proxy address (host:port)"},
		&cli.IntFlag{Name: "min", Value: 64, Usage: "minimum payload size"},
		&cli.IntFlag{Name: "max", Value: 65536, Usage: "maximum payload size"},
		&cli.DurationFlag{Name: "interval", Value: time.Millisecond, Usage: "interval between packets"},
		&cli.IntFlag{Name: "count", Value: 0, Usage: "number of packets to send (0 = unlimited)"},
	},
	Action: func(c *cli.Context) error {
		minSize, maxSize := c.Int("min"), c.Int("max")
		if minSize < 1 {
			minSize = 1
		}

		var conn net.Conn
		var err error
		if socks := c.String("socks"); socks != "" {
			conn, err = dialSocks(socks, c.String("target"))
		} else {
			conn, err = net.Dial("tcp", c.String("target"))
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "dial: %v\n", err)
			os.Exit(1)
		}
		defer conn.Close()

		sent, fail, maxCount := 0, 0, c.Int("count")
		buf := make([]byte, maxSize+8)
		interval := c.Duration("interval")
		start := time.Now()

		for maxCount == 0 || sent < maxCount {
			sz := minSize + mrand.IntN(maxSize-minSize+1)
			payload := make([]byte, sz)
			rand.Read(payload)

			var cksum [4]byte
			for i, b := range payload {
				cksum[i%4] ^= b
			}

			binary.BigEndian.PutUint32(buf[:4], uint32(sz))
			copy(buf[4:], payload)
			copy(buf[4+sz:], cksum[:])

			if _, err := conn.Write(buf[:8+sz]); err != nil {
				fmt.Fprintf(os.Stderr, "write failed at pkt %d (size %d): %v\n", sent, sz, err)
				fail++
				break
			}
			if _, err := io.ReadFull(conn, buf[:8+sz]); err != nil {
				fmt.Fprintf(os.Stderr, "read failed at pkt %d (size %d): %v\n", sent, sz, err)
				fail++
				break
			}

			if retSz := binary.BigEndian.Uint32(buf[:4]); int(retSz) != sz {
				fmt.Fprintf(os.Stderr, "size mismatch at pkt %d: sent %d got %d\n", sent, sz, retSz)
				fail++
			}
			bad := false
			for i := range payload {
				if buf[4+i] != payload[i] {
					fmt.Fprintf(os.Stderr, "data mismatch at pkt %d offset %d: exp 0x%02x got 0x%02x\n", sent, i, payload[i], buf[4+i])
					fail, bad = fail+1, true
					break
				}
			}
			if bad {
				break
			}
			sent++
			time.Sleep(interval)
		}

		elapsed := time.Since(start)
		fmt.Printf("sent=%d fail=%d elapsed=%v %.0f pkt/s\n", sent, fail, elapsed.Round(time.Millisecond), float64(sent)/elapsed.Seconds())
		return nil
	},
}
