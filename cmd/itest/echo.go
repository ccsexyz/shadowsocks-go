package main

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/urfave/cli/v2"
)

var echoCommand = &cli.Command{
	Name:  "echo",
	Usage: "start a TCP echo server",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "addr", Value: ":9999", Usage: "listen address"},
		&cli.DurationFlag{Name: "delay", Usage: "delay before echoing each chunk"},
	},
	Action: func(c *cli.Context) error {
		return runEchoServer(c.String("addr"), c.Duration("delay"))
	},
}

func runEchoServer(addr string, delay time.Duration) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("echo on %s (delay=%v)", ln.Addr(), delay)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleEcho(conn, delay)
	}
}

func handleEcho(c net.Conn, delay time.Duration) {
	defer c.Close()
	if delay > 0 {
		buf := make([]byte, 65536)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				time.Sleep(delay)
				c.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	} else {
		io.Copy(c, c)
	}
}

// startEcho starts an echo server on a random port and returns its address.
// Used by scenario orchestration.
func startEcho(delay time.Duration) (string, func(), error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleEcho(conn, delay)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }, nil
}
