package server

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func TestTLSObfsRoundTrip(t *testing.T) {
	methods := []struct {
		name   string
		method string
		pwd    string
	}{
		{"non2022", "aes-256-gcm", "test-key-01234567"},
		{"2022", "2022-blake3-aes-256-gcm", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			// Each sub-test gets its own echo server to avoid cross-test interference.
			_, echoHost, echoPort := echoServer(t)

			srv := &ss.Config{}
			srv.Type = "server"
			srv.Localaddr = "127.0.0.1:0"
			srv.Method = m.method
			srv.Password = m.pwd
			srv.Obfs = true
			srv.ObfsMethod = "tls"
			ss.CheckConfig(srv)
			defer srv.Close()

			var handlers []ss.AcceptHandler
			handlers = append(handlers, ss.LimitHandler, ss.ObfsHandler)
			if m.name == "2022" {
				handlers = append(handlers, ss.SS2022Handler)
			} else {
				handlers = append(handlers, ss.SSHandler)
			}
			sln, err := ss.Listen(srv.Localaddr, srv, handlers)
			if err != nil {
				t.Fatal("server listen:", err)
			}
			defer sln.Close()
			srvAddr := sln.Addr().String()

			go func() {
				for {
					c, err := sln.Accept()
					if err != nil {
						return
					}
					go RemoteHandler(c.(*ss.AcceptedConn))
				}
			}()

			cli := &ss.Config{}
			cli.Type = "local"
			cli.Localaddr = "127.0.0.1:0"
			cli.Remoteaddr = srvAddr
			cli.Method = m.method
			cli.Password = m.pwd
			cli.Obfs = true
			cli.ObfsMethod = "tls"
			ss.CheckConfig(cli)
			defer cli.Close()

			cln, err := ss.Listen(cli.Localaddr, cli, []ss.AcceptHandler{ss.LimitHandler, ss.SocksAcceptor})
			if err != nil {
				t.Fatal("local listen:", err)
			}
			defer cln.Close()
			cliAddr := cln.Addr().String()

			go func() {
				for {
					c, err := cln.Accept()
					if err != nil {
						return
					}
					go tcpLocalHandler(c.(*ss.AcceptedConn))
				}
			}()

			time.Sleep(500 * time.Millisecond)

			sizes := []int{2000, 65536}
			for _, sz := range sizes {
				t.Run("size_"+strconv.Itoa(sz), func(t *testing.T) {
					// First connection through a freshly started obfs+SS chain
					// can fail due to internal timing; retry once to absorb this.
					var lastErr error
					for attempt := 0; attempt < 3; attempt++ {
						conn, err := net.Dial("tcp", cliAddr)
						if err != nil {
							lastErr = err
							time.Sleep(100 * time.Millisecond)
							continue
						}
						socks5Connect(t, conn, echoHost, echoPort)

						payload := make([]byte, sz)
						for i := range payload {
							payload[i] = byte(i)
						}
						conn.Write(payload)

						resp := make([]byte, sz)
						_, err = io.ReadFull(conn, resp)
						conn.Close()
						if err != nil {
							lastErr = fmt.Errorf("read back: %v", err)
							time.Sleep(100 * time.Millisecond)
							continue
						}

						for i := range resp {
							if resp[i] != payload[i] {
								t.Fatalf("byte mismatch at offset %d: expected 0x%02x got 0x%02x", i, payload[i], resp[i])
							}
						}
						lastErr = nil
						break
					}
					if lastErr != nil {
						t.Fatal(lastErr)
					}
				})
			}
		})
	}
}
