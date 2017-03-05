package main

import (
	"log"
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
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
	if len(remain) < 1 || len(remain) < 1+int(remain[0]) {
		return
	}
	nbytes := int(remain[0])
	target := string(remain[1 : 1+nbytes])
	rconn, err := net.Dial("udp", target)
	if err != nil {
		return
	}
	defer rconn.Close()
	if len(remain) > 1+nbytes {
		rconn.Write(remain[1+nbytes:])
	}
	remain = nil
	conn = ss.NewConn2(conn)
	ss.Pipe(conn, rconn)
}
