package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/urfave/cli/v2"
)

var udpfwdCommand = &cli.Command{
	Name:  "udpfwd",
	Usage: "UDP-to-SOCKS5 forwarder",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "listen", Aliases: []string{"l"}, Value: ":1053", Usage: "local UDP listen address"},
		&cli.StringFlag{Name: "socks", Value: "127.0.0.1:1080", Usage: "SOCKS5 proxy address (TCP)"},
		&cli.StringFlag{Name: "target", Required: true, Usage: "forward target host:port"},
		&cli.IntFlag{Name: "buf", Value: 2048, Usage: "UDP buffer size"},
		&cli.DurationFlag{Name: "idle", Value: 60 * time.Second, Usage: "client session idle timeout"},
	},
	Action: func(c *cli.Context) error {
		targetHost, targetPort, err := parseTarget(c.String("target"))
		if err != nil {
			return fmt.Errorf("invalid target: %w", err)
		}

		relayAddr, err := socks5UDPAssociate(c.String("socks"))
		if err != nil {
			return fmt.Errorf("SOCKS5 UDP ASSOCIATE failed: %w", err)
		}
		log.Printf("SOCKS5 relay at %s, forwarding to %s", relayAddr, c.String("target"))

		laddr, err := net.ResolveUDPAddr("udp", c.String("listen"))
		if err != nil {
			return err
		}
		localConn, err := net.ListenUDP("udp", laddr)
		if err != nil {
			return err
		}
		defer localConn.Close()
		log.Printf("listening on UDP %s", localConn.LocalAddr())

		var (
			sessions = make(map[string]*fwSession)
			mu       sync.Mutex
			done     = make(chan struct{})
		)

		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		go func() {
			<-sigCh
			log.Println("shutting down...")
			close(done)
		}()

		bufSize, idleTimeout := c.Int("buf"), c.Duration("idle")
		go reapSessions(&mu, sessions, idleTimeout, done)

		buf := make([]byte, bufSize)
		for {
			select {
			case <-done:
				return nil
			default:
			}
			localConn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, clientAddr, err := localConn.ReadFromUDP(buf)
			if err != nil {
				if !os.IsTimeout(err) {
					return err
				}
				continue
			}
			key := clientAddr.String()
			mu.Lock()
			s, ok := sessions[key]
			if !ok {
				s, err = newFwSession(relayAddr, clientAddr, localConn, bufSize)
				if err != nil {
					log.Printf("new session for %s: %v", key, err)
					mu.Unlock()
					continue
				}
				sessions[key] = s
			}
			s.lastUsed = time.Now()
			mu.Unlock()

			pkt := buildSocks5UDPPacket(targetHost, targetPort, buf[:n])
			s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := s.conn.Write(pkt); err != nil {
				log.Printf("write to relay for %s: %v", key, err)
			}
		}
	},
}

func reapSessions(mu *sync.Mutex, sessions map[string]*fwSession, idleTimeout time.Duration, done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			mu.Lock()
			for key, s := range sessions {
				if time.Since(s.lastUsed) > idleTimeout {
					s.conn.Close()
					delete(sessions, key)
				}
			}
			mu.Unlock()
		}
	}
}

type fwSession struct {
	conn     *net.UDPConn
	lastUsed time.Time
}

func newFwSession(relayAddr string, clientAddr *net.UDPAddr, localConn *net.UDPConn, bufSize int) (*fwSession, error) {
	rAddr, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return nil, err
	}
	s := &fwSession{conn: conn, lastUsed: time.Now()}
	go func() {
		buf := make([]byte, bufSize)
		for {
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			payload, err := parseSocks5UDPResponse(buf[:n])
			if err != nil {
				continue
			}
			localConn.WriteToUDP(payload, clientAddr)
		}
	}()
	return s, nil
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

func parseTarget(addr string) (host string, port int, err error) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err = net.LookupPort("udp", p)
	if err != nil {
		return "", 0, err
	}
	return h, port, nil
}
