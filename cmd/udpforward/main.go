// Command udpforward listens on a local UDP port and forwards each client's
// packets through a dedicated UDP connection to a SOCKS5 relay, targeting a
// fixed address. Each local client address gets its own relay socket, so the
// kernel handles response demultiplexing — no application-layer matching needed.
//
// Usage:
//
//	udpforward -l :1053 -socks 127.0.0.1:1080 -target 8.8.8.8:53
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"
)

var (
	localAddr   = flag.String("l", ":1053", "local UDP listen address")
	socksAddr   = flag.String("socks", "127.0.0.1:1080", "SOCKS5 proxy address (TCP)")
	targetAddr  = flag.String("target", "", "forward target host:port (required)")
	bufferSize  = flag.Int("buf", 2048, "UDP buffer size")
	idleTimeout = flag.Duration("idle", 60*time.Second, "client session idle timeout")
)

func main() {
	flag.Parse()
	if *targetAddr == "" {
		fmt.Fprintf(os.Stderr, "usage: udpforward -l :1053 -socks 127.0.0.1:1080 -target host:port\n")
		os.Exit(1)
	}

	targetHost, targetPort, err := parseTarget(*targetAddr)
	if err != nil {
		log.Fatalf("invalid target %q: %v", *targetAddr, err)
	}

	// SOCKS5 UDP ASSOCIATE — get the relay address
	relayAddr, err := socks5UDPAssociate(*socksAddr)
	if err != nil {
		log.Fatalf("SOCKS5 UDP ASSOCIATE failed: %v", err)
	}
	log.Printf("SOCKS5 relay at %s, forwarding to %s", relayAddr, *targetAddr)

	// Listen on local UDP port
	laddr, err := net.ResolveUDPAddr("udp", *localAddr)
	if err != nil {
		log.Fatalf("resolve %s: %v", *localAddr, err)
	}
	localConn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *localAddr, err)
	}
	defer localConn.Close()
	log.Printf("listening on UDP %s", localConn.LocalAddr())

	var (
		sessions = make(map[string]*clientSession)
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

	// Reap idle sessions
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				mu.Lock()
				for key, s := range sessions {
					if time.Since(s.lastUsed) > *idleTimeout {
						s.conn.Close()
						delete(sessions, key)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, *bufferSize)
	for {
		select {
		case <-done:
			return
		default:
		}
		localConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, clientAddr, err := localConn.ReadFromUDP(buf)
		if err != nil {
			if !os.IsTimeout(err) {
				return
			}
			continue
		}

		key := clientAddr.String()
		mu.Lock()
		s, ok := sessions[key]
		if !ok {
			s, err = newClientSession(relayAddr, clientAddr, localConn)
			if err != nil {
				log.Printf("new session for %s: %v", key, err)
				mu.Unlock()
				continue
			}
			sessions[key] = s
		}
		s.lastUsed = time.Now()
		mu.Unlock()

		// Build SOCKS5 UDP header + payload
		pkt := buildSocks5UDPPacket(targetHost, targetPort, buf[:n])
		s.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := s.conn.Write(pkt); err != nil {
			log.Printf("write to relay for %s: %v", key, err)
		}
	}
}

type clientSession struct {
	conn     *net.UDPConn
	lastUsed time.Time
}

func newClientSession(relayAddr string, clientAddr *net.UDPAddr, localConn *net.UDPConn) (*clientSession, error) {
	rAddr, err := net.ResolveUDPAddr("udp", relayAddr)
	if err != nil {
		return nil, err
	}
	// Each client gets its own UDP socket → kernel demuxes responses by 5-tuple.
	conn, err := net.DialUDP("udp", nil, rAddr)
	if err != nil {
		return nil, err
	}
	s := &clientSession{conn: conn, lastUsed: time.Now()}

	// Read responses from relay and forward back to this specific client.
	go func() {
		buf := make([]byte, *bufferSize)
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

func socks5UDPAssociate(addr string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial SOCKS5: %w", err)
	}
	defer conn.Close()

	// Method negotiation
	conn.Write([]byte{5, 1, 0})
	buf := make([]byte, 512)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return "", fmt.Errorf("handshake: %w", err)
	}
	if buf[0] != 5 || buf[1] != 0 {
		return "", fmt.Errorf("method rejected: %x", buf[:2])
	}

	// UDP ASSOCIATE
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
	pkt = append(pkt, 0, 0, 0) // RSV + FRAG
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
