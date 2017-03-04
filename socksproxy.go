package main

import (
	"fmt"
	"log"
	"net"
	"strconv"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunSocksProxyServer(c *ss.Config) {
	RunTCPServer(c.Localaddr, c, ss.ListenSocks5, socksProxyHandler)
}

func socksProxyHandler(conn net.Conn, c *ss.Config) {
	defer conn.Close()
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}
	if buf[0] != 5 || buf[1] != 1 {
		return
	}
	buf = buf[3:n]
	host, port, _ := ss.ParseAddr(buf)
	if len(host) == 0 {
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
	_, err = conn.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	if err != nil {
		return
	}
	log.Println("proxy", host, port, "to", rconn.RemoteAddr().String(), "from", conn.RemoteAddr().String())
	ss.Pipe(conn, rconn)
}
