package main

import (
	"log"
	"net"
	"strconv"
	"time"
)

func RunTCPRemoteServer(address string, info *ssinfo) {
	if info.ivlen == 0 {
		info.ivlen = getIvLen(info.method)
	}
	lis, err := Listen(address, info)
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go tcpRemoteHandler(conn)
	}
}

func tcpRemoteHandler(conn net.Conn) {
	defer conn.Close()
	C, ok := conn.(*Conn)
	var timer *time.Timer
	if ok {
		C.xu1s = true
		timer = time.AfterFunc(time.Second*4, func() {
			// FIXME
			if C.xu1s {
				conn.Close()
			}
		})
	}
	buf := make([]byte, buffersize)
	n, err := conn.Read(buf)
	if timer != nil {
		timer.Stop()
		timer = nil
	}
	if err != nil {
		log.Println(err)
		return
	}
	host, port, data := ParseAddr(buf[:n])
	if len(host) == 0 {
		log.Printf("recv a unexpected header from %s.", conn.RemoteAddr().String())
		return
	}
	rconn, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		log.Println(err)
		return
	}
	defer rconn.Close()
	if C != nil {
		C.xu1s = false
	}
	if len(data) != 0 {
		_, err = rconn.Write(data)
		if err != nil {
			log.Println(err)
			return
		}
	}
	buf = nil
	pipe(conn, rconn)
}
