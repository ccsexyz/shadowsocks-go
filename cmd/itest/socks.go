package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// dialSocks connects to target through a SOCKS5 proxy.
func dialSocks(socksAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", socksAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	c.Write([]byte{5, 1, 0})
	buf := make([]byte, 512)
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks handshake: %w", err)
	}
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		c.Close()
		return nil, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		c.Close()
		return nil, err
	}
	ip := net.ParseIP(host)
	req := []byte{5, 1, 0}
	if ip != nil && ip.To4() != nil {
		req = append(req, 1)
		req = append(req, ip.To4()...)
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))
	c.Write(req)
	if _, err := io.ReadFull(c, buf[:10]); err != nil {
		c.Close()
		return nil, fmt.Errorf("socks connect: %w", err)
	}
	if buf[1] != 0 {
		c.Close()
		return nil, fmt.Errorf("socks connect failed: code %d", buf[1])
	}
	return c, nil
}

// socks5UDPAssociate opens a SOCKS5 UDP relay and returns the relay address.
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
