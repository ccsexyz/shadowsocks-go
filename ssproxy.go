package main

import "net"
import (
	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
	"time"
	"log"
	"strconv"
	"fmt"
)

func RunSSProxyServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSS, ssproxyHandler)
}

func ssproxyHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	if len(c.Backends) == 0 {
		log.Println("no backends in config file")
		return
	}
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
	die := make(chan bool)
	errch := make(chan error, len(c.Backends))
	conch := make(chan net.Conn, len(c.Backends))
	for _, v := range c.Backends {
		go func(v *ss.Config) {
			rconn, err := ss.DialSS(net.JoinHostPort(host, strconv.Itoa(port)), v.Remoteaddr, v)
			if err != nil {
				select {
				case <-die:
				case errch<-fmt.Errorf("cannot connect to %s : %s", v.Remoteaddr, err.Error()):
				}
				return
			}
			select {
			case <-die:
				rconn.Close()
			case conch<-rconn:
			}
		}(v)
	}
	var rconn net.Conn
	for i := 0; i < len(c.Backends); i++ {
		select {
		case rconn = <-conch:
			close(die)
			i = len(c.Backends)
		case e := <-errch:
			log.Println(e)
		}
	}
	if rconn == nil {
		log.Println("no available backends")
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
	log.Println("proxy", host, port, "to", rconn.RemoteAddr().String(), "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
