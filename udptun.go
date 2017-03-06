package main

import (
	"log"
	"net"
	"sync"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

type TunUDPConn struct {
	net.UDPConn
}

func (c *TunUDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	n = len(b)
	host, _, data := ss.ParseAddr(b)
	if len(host) == 0 {
		return
	}
	return c.UDPConn.WriteTo(data, addr)
}

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
			log.Println("tunnel to", c.Remoteaddr, "through", rconn.RemoteAddr())
			rconn.Write(b)
			return
		}
		RunUDPServer(conn, nil, handle, create)
	} else {
		buf := make([]byte, 2048)
		addr, err := net.ResolveUDPAddr("udp", c.Remoteaddr)
		if err != nil {
			log.Fatal(err)
		}
		hdrlen := ss.PutHeader(buf, addr.IP.String(), addr.Port)
		var lock sync.Mutex
		handle = func(sess *udpSession, b []byte) {
			lock.Lock()
			copy(buf[hdrlen:], b)
			sess.conn.Write(buf[:hdrlen+len(b)])
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
			_, err = rconn.Write(buf[:hdrlen+len(b)])
			lock.Unlock()
			if err != nil {
				return
			}
			log.Println("tunnel to", c.Remoteaddr, "through", rconn.RemoteAddr())
			return
		}
		tconn := &TunUDPConn{UDPConn: *conn}
		RunUDPServer(tconn, nil, handle, create)
	}
}
