package main

import (
	"io"
	"log"
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
	C := conn.(*ss.Conn)
	target := C.Target
	if len(target.Addr) == 0 {
		return
	}
	if target.Addr == ss.Udprelayaddr {
		C.Xu0s()
		if c.UDPOverTCP {
			udpRelayOverTCP(conn, target.Remain)
		}
		return
	}
	rconn, err := net.Dial("tcp", target.Addr)
	if err != nil {
		log.Println(err)
		return
	}
	defer rconn.Close()
	C.Xu0s()
	if len(target.Remain) != 0 {
		_, err = rconn.Write(target.Remain)
		if err != nil {
			log.Println(err)
			return
		}
	}
	log.Println("connect to", target.Addr, "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}

func udpRelayOverTCP(conn net.Conn, remain []byte) {
	var nbytes int
	var target string
	buf := make([]byte, 256)
	if len(remain) == 0 {
		_, err := io.ReadFull(conn, buf[:1])
		if err != nil {
			return
		}
		nbytes = int(buf[0])
	} else {
		nbytes = int(remain[0])
		remain = remain[1:]
	}
	if len(remain) >= nbytes {
		target = string(remain[:nbytes])
		remain = remain[nbytes:]
	} else {
		copy(buf, remain)
		_, err := io.ReadFull(conn, buf[len(remain):nbytes])
		if err != nil {
			return
		}
		target = string(buf[:nbytes])
		remain = nil
	}
	buf = nil
	rconn, err := net.Dial("udp", target)
	if err != nil {
		return
	}
	defer rconn.Close()
	if len(remain) > 0 {
		rconn.Write(remain)
	}
	conn = ss.NewConn2(conn)
	ss.Pipe(conn, rconn)
}
