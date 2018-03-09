package main

import (
	"context"
	"log"
	"net"
	"time"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

type Dialer = ss.Dialer
type ConnCtx = ss.ConnCtx
type Conn = ss.Conn
type Acceptor = ss.Acceptor
type DstAddr = ss.DstAddr

func runTCPServer(ctx context.Context, address string, handler func(net.Conn)) {
	lis, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		defer lis.Close()
		<-ctx.Done()
	}()
	for {
		conn, err := lis.Accept()
		if err != nil {
			if operr, ok := err.(*net.OpError); ok {
				if operr.Temporary() {
					time.Sleep(time.Millisecond * 10)
					continue
				}
			}
			return
		}
		go handler(conn)
	}
}
