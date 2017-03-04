package main

import (
	"log"
	"net"
	"strconv"
	"time"
)

func RunTCPRemoteServer(c *Config) {
	if c.ivlen == 0 {
		c.ivlen = getIvLen(c.Method)
	}
	lis, err := ListenSS(c.Server, c)
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
	if !ok || C == nil {
		return
	}
	C.xu1s = true
	timer = time.AfterFunc(time.Second*4, func() {
		// FIXME
		if C.xu1s {
			conn.Close()
		}
	})
	buf := C.wbuf
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
	log.Println("connect to ", host, port, "from", conn.RemoteAddr().String())
	pipe(conn, rconn)
}
