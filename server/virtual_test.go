package server

import (
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func echoServer(t *testing.T) (string, string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(conn)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return ln.Addr().String(), host, port
}

func socks5Connect(t *testing.T, conn net.Conn, host string, port int) {
	t.Helper()
	conn.Write([]byte{5, 1, 0})
	buf := make([]byte, 512)
	io.ReadFull(conn, buf[:2])

	req := []byte{5, 1, 0, 3, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xff))
	conn.Write(req)
	io.ReadFull(conn, buf[:10])
	if buf[1] != 0 {
		t.Fatalf("SOCKS5 CONNECT failed: %x", buf[:2])
	}
}

func TestVirtualPipeline(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	srv := &ss.Config{}
	srv.Type = "server"
	srv.Localaddr = "@vpipe-srv"
	srv.Method = "aes-256-gcm"
	srv.Password = "test"
	ss.CheckConfig(srv)
	defer srv.Close()
	go RunTCPRemoteServer(srv)

	cli := &ss.Config{}
	cli.Type = "local"
	cli.Localaddr = "@vpipe-cli"
	cli.Remoteaddr = "@vpipe-srv"
	cli.Method = "aes-256-gcm"
	cli.Password = "test"
	ss.CheckConfig(cli)
	defer cli.Close()
	go RunTCPLocalServer(cli)

	time.Sleep(200 * time.Millisecond)

	client, err := ss.DialVirtual("@vpipe-cli")
	if err != nil {
		t.Fatalf("DialVirtual: %v", err)
	}
	defer client.Close()

	socks5Connect(t, client, echoHost, echoPort)

	payload := "hello-pipeline"
	client.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(client, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}
}

func TestVirtualMultiplePipelines(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	const numPipes = 3
	var cfgs []*ss.Config

	for i := range numPipes {
		srvName := "@mp-srv-" + strconv.Itoa(i)
		cliName := "@mp-cli-" + strconv.Itoa(i)

		srv := &ss.Config{}
		srv.Type = "server"
		srv.Localaddr = srvName
		srv.Method = "aes-256-gcm"
		srv.Password = "test-" + strconv.Itoa(i)
		ss.CheckConfig(srv)
		go RunTCPRemoteServer(srv)

		cli := &ss.Config{}
		cli.Type = "local"
		cli.Localaddr = cliName
		cli.Remoteaddr = srvName
		cli.Method = "aes-256-gcm"
		cli.Password = "test-" + strconv.Itoa(i)
		ss.CheckConfig(cli)
		go RunTCPLocalServer(cli)

		cfgs = append(cfgs, srv, cli)
	}
	defer func() {
		for _, c := range cfgs {
			c.Close()
		}
	}()

	time.Sleep(300 * time.Millisecond)

	var wg sync.WaitGroup
	for i := range numPipes {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			cliName := "@mp-cli-" + strconv.Itoa(id)

			client, err := ss.DialVirtual(cliName)
			if err != nil {
				t.Errorf("pipe %d: DialVirtual: %v", id, err)
				return
			}
			defer client.Close()

			socks5Connect(t, client, echoHost, echoPort)

			payload := []byte("pipe-" + strconv.Itoa(id) + "-data")
			client.Write(payload)
			resp := make([]byte, len(payload))
			io.ReadFull(client, resp)
			if string(resp) != string(payload) {
				t.Errorf("pipe %d: expected '%s', got '%s'", id, payload, string(resp))
			}
		}(i)
	}
	wg.Wait()
}

func TestVirtualServiceChaining(t *testing.T) {
	_, echoHost, echoPort := echoServer(t)

	hop2 := &ss.Config{}
	hop2.Type = "server"
	hop2.Localaddr = "@chain-hop2"
	hop2.Method = "aes-256-gcm"
	hop2.Password = "hop2"
	ss.CheckConfig(hop2)
	defer hop2.Close()
	go RunTCPRemoteServer(hop2)

	hop1 := &ss.Config{}
	hop1.Type = "local"
	hop1.Localaddr = "@chain-hop1"
	hop1.Remoteaddr = "@chain-hop2"
	hop1.Method = "aes-256-gcm"
	hop1.Password = "hop2"
	ss.CheckConfig(hop1)
	defer hop1.Close()
	go RunTCPLocalServer(hop1)

	time.Sleep(200 * time.Millisecond)

	client, err := ss.DialVirtual("@chain-hop1")
	if err != nil {
		t.Fatalf("DialVirtual: %v", err)
	}
	defer client.Close()

	socks5Connect(t, client, echoHost, echoPort)

	payload := "through-two-hops"
	client.Write([]byte(payload))
	resp := make([]byte, len(payload))
	io.ReadFull(client, resp)
	if string(resp) != payload {
		t.Errorf("expected '%s', got '%s'", payload, string(resp))
	}
}
