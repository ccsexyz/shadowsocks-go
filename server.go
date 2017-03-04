package main

import (
	"log"
	"net"
	"strconv"
	"time"
	
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPRemoteServer(c *ss.Config) {
	ss.CheckConfig(c)
	lis, err := ss.ListenSS(c.Server, c)
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
	C, ok := conn.(*ss.Conn)
	var timer *time.Timer
	if !ok || C == nil {
		return
	}
	C.Xu1s()
	timer = time.AfterFunc(time.Second*4, func() {
		C.Close()
	})
	buf := C.Wbuf()
	n, err := conn.Read(buf)
	if timer != nil {
		timer.Stop()
		timer = nil
	}
	if err != nil {
		log.Println(err)
		return
	}
	host, port, data := ss.ParseAddr(buf[:n])
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
		C.Xu0s()
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
	ss.Pipe(conn, rconn)
}
