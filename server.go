package main

import (
	"io"
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunMultiTCPRemoteServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenMultiSS, tcpRemoteHandler)
}

func RunTCPRemoteServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSS, tcpRemoteHandler)
}

func tcpRemoteHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	C := conn.(*ss.DstConn).Conn.(*ss.RemainConn).Conn.(*ss.Conn)
	target := conn.(*ss.DstConn).GetDst()
	if len(target) == 0 {
		c.LogD("target length is 0")
		return
	}
	if target == ss.Udprelayaddr {
		C.Xu0s()
		if c.UDPOverTCP {
			udpRelayOverTCP(conn)
		}
		return
	}
	rconn, err := net.Dial("tcp", target)
	if err != nil {
		c.Log(err)
		return
	}
	defer rconn.Close()
	C.Xu0s()
	c.Log("connect to", target, "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}

func udpRelayOverTCP(conn net.Conn) {
	buf := make([]byte, 256)
	_, err := io.ReadFull(conn, buf[:1])
	if err != nil {
		return
	}
	nbytes := int(buf[0])
	_, err = io.ReadFull(conn, buf[:nbytes])
	if err != nil {
		return
	}
	target := string(buf[:nbytes])
	buf = nil
	rconn, err := net.Dial("udp", target)
	if err != nil {
		return
	}
	defer rconn.Close()
	conn = ss.NewConn2(conn)
	ss.Pipe(conn, rconn)
}
