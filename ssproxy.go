package main

import (
	"fmt"
	"log"
	"net"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
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
	C := conn.(*ss.Conn)
	target := C.Target
	if len(target.Addr) == 0 {
		return
	}
	die := make(chan bool)
	errch := make(chan error, len(c.Backends))
	conch := make(chan net.Conn, len(c.Backends))
	for _, v := range c.Backends {
		go func(v *ss.Config) {
			rconn, err := ss.DialSS(target.Addr, v.Remoteaddr, v)
			if err != nil {
				select {
				case <-die:
				case errch <- fmt.Errorf("cannot connect to %s : %s", v.Remoteaddr, err.Error()):
				}
				return
			}
			select {
			case <-die:
				rconn.Close()
			case conch <- rconn:
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
	if len(target.Remain) != 0 {
		_, err := rconn.Write(target.Remain)
		if err != nil {
			log.Println(err)
			return
		}
	}
	log.Println("proxy", target.Addr, "to", rconn.RemoteAddr().String(), "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
