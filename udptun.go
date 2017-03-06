package main

import (
	"encoding/binary"
	"log"
	"net"
	"sync"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunUDPTunServer(c *ss.Config) {
	conn, err := newUDPListener(c.Localaddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	var handle func(*udpSession, []byte)
	var create func([]byte) (net.Conn, func(), []byte, error)
	if c.Backend.UDPOverTCP {
		handle = func(sess *udpSession, b []byte) {
			sess.conn.Write(b)
		}
		create = func(b []byte) (rconn net.Conn, clean func(), header []byte, err error) {
			rconn, err = ss.DialUDPOverTCP(c.Remoteaddr, c.Backend.Remoteaddr, c.Backend)
			if err != nil {
				return
			}
			// log.Println("tunnel to", c.Remoteaddr, "through", rconn.RemoteAddr())
			rconn.Write(b)
			return
		}
	} else {
		buf := make([]byte, 2048)
		addr, err := net.ResolveUDPAddr("udp", c.Remoteaddr)
		if err != nil {
			log.Fatal(err)
		}
		ipstr := addr.IP.String()
		buf[0] = byte(len(ipstr))
		copy(buf[1:], []byte(ipstr))
		binary.BigEndian.PutUint16(buf[1+len(ipstr):], uint16(addr.Port))
		hdrlen := int(buf[0]) + 3
		var lock sync.Mutex
		handle = func(sess *udpSession, b []byte) {
			lock.Lock()
			copy(buf[hdrlen:], b)
			sess.conn.Write(buf[hdrlen+len(b):])
			lock.Unlock()
		}
		create = func(b []byte) (rconn net.Conn, clean func(), header []byte, err error) {
			rconn, err = net.Dial("udp", c.Backend.Remoteaddr)
			if err != nil {
				return
			}
			rconn = ss.NewUDPConn(rconn.(*net.UDPConn), c.Backend)
			lock.Lock()
			copy(buf[hdrlen:], b)
			rconn.Write(buf[hdrlen+len(b):])
			lock.Unlock()
			return
		}
	}

	RunUDPServer(conn, nil, handle, create)
}
