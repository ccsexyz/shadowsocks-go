package main

import (
	"log"
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"io"
)

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
		if c.UdpOverTCP {
			udpRelayOverTCP(conn)
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

func udpRelayOverTCP(conn net.Conn) {
	buf := make([]byte, 2048)
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
	rconn, err := net.Dial("udp", target)
	if err != nil {
		return
	}
	defer rconn.Close()
	conn = ss.NewConn2(conn)
	ss.Pipe(conn, rconn)
}