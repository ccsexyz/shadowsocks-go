package main

import (
	"log"
	"net"
	"strconv"

	"encoding/binary"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPLocalServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, tcpLocalHandler)
}

func tcpLocalHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	ver := buf[0]
	cmd := buf[1]
	if ver != 5 || (cmd != 1 && cmd != 3) || (!c.UdpRelay && cmd == 3) {
		return
	}
	host, port, _ := ss.ParseAddr(buf[3:n])
	if len(host) == 0 {
		return
	}
	if c.UdpRelay && cmd == 3 {
		addr, err := net.ResolveUDPAddr("udp", c.Localaddr)
		if err != nil {
			return
		}
		copy(buf, []byte{5, 0, 0, 1})
		copy(buf[4:], addr.IP.To4())
		binary.BigEndian.PutUint16(buf[8:], uint16(addr.Port))
		_, err = conn.Write(buf[:10])
		for err == nil {
			_, err = conn.Read(buf)
		}
		return
	}
	rconn, err := ss.DialSS(net.JoinHostPort(host, strconv.Itoa(port)), c.Remoteaddr, c)
	if err != nil {
		return
	}
	defer rconn.Close()
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return
	}
	log.Println("connect to ", host, port, "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
