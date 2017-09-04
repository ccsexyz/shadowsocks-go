package main

import (
	"net"
	"sync"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

type TunUDPConn struct {
	net.UDPConn
}

func (c *TunUDPConn) WriteTo(b []byte, addr net.Addr) (n int, err error) {
	n = len(b)
	_, data, err := ss.ParseAddr(b)
	if err != nil {
		return
	}
	return c.UDPConn.WriteTo(data, addr)
}

func RunUDPTunServer(c *ss.Config) {
	conn, err := newUDPListener(c.Localaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	defer conn.Close()
	var handle func(*udpSession, []byte)
	var create func([]byte, net.Addr) (net.Conn, func(), []byte, error)
	buf := make([]byte, 2048)
	addr, err := net.ResolveUDPAddr("udp", c.Remoteaddr)
	if err != nil {
		c.Logger.Fatal(err)
	}
	hdrlen := ss.PutHeader(buf, addr.IP.String(), addr.Port)
	var lock sync.Mutex
	handle = func(sess *udpSession, b []byte) {
		lock.Lock()
		copy(buf[hdrlen:], b)
		sess.conn.Write(buf[:hdrlen+len(b)])
		lock.Unlock()
	}
	create = func(b []byte, from net.Addr) (rconn net.Conn, clean func(), header []byte, err error) {
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
		c.Log("tunnel to", c.Remoteaddr, "through", rconn.RemoteAddr())
		return
	}
	tconn := &TunUDPConn{UDPConn: *conn}
	RunUDPServer(tconn, c, nil, handle, create)
}
