package main

import (
	"log"
	"net"

	"strconv"
	"sync"
	"time"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

type relaySession struct {
	conn   net.Conn
	live   bool
	from   *net.UDPAddr
	die    chan bool
	header []byte
}

func (sess *relaySession) Close() {
	select {
	case <-sess.die:
	default:
		sess.conn.Close()
		close(sess.die)
	}
}

func RunUDPRemoteServer(c *ss.Config) {
	die := make(chan bool)
	defer close(die)

	laddr, err := net.ResolveUDPAddr("udp", c.Localaddr)
	if err != nil {
		log.Fatal(err)
	}
	uconn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	conn := ss.NewUDPConn(uconn, c)

	rbuf := make([]byte, 2048)
	sessions := make(map[string]*relaySession)
	var lock sync.Mutex

	go func() {
		ticker := time.NewTicker(time.Second * 30)
		for {
			select {
			case <-die:
				return
			case <-ticker.C:
				lock.Lock()
				for k, v := range sessions {
					if v.live {
						v.live = false
					} else {
						v.Close()
						delete(sessions, k)
					}
				}
				lock.Unlock()
			}
		}
	}()

	for {
		n, addr, err := conn.ReadFrom(rbuf)
		if err != nil {
			log.Println(err)
			return
		}
		addrstr := addr.String()
		host, port, data := ss.ParseAddr(rbuf[:n])
		log.Println(host, port, data)
		if len(host) == 0 {
			continue
		}
		target := net.JoinHostPort(host, strconv.Itoa(port))
		lock.Lock()
		sess, ok := sessions[addrstr]
		lock.Unlock()
		if ok {
			sess.live = true
			sess.conn.Write(data)
			continue
		}
		rconn, err := net.Dial("udp", target)
		if err != nil {
			log.Fatal(err)
			continue
		}
		header := make([]byte, n-len(data))
		copy(header, rbuf)
		sess = &relaySession{conn: rconn, live: true, from: addr.(*net.UDPAddr), header: header, die: make(chan bool)}
		lock.Lock()
		sessions[addrstr] = sess
		lock.Unlock()
		rconn.Write(data)
		go func(sess *relaySession) {
			defer sess.Close()
			b := make([]byte, 2048)
			copy(b, sess.header)
			for {
				n, err := sess.conn.Read(b[len(sess.header):])
				if err != nil {
					return
				}
				select {
				case <-sess.die:
					return
				default:
				}
				_, err = conn.WriteTo(b[:n+len(sess.header)], sess.from)
				if err != nil {
					return
				}
			}
		}(sess)
	}
}

func RunUDPLocalServer(c *ss.Config) {
	die := make(chan bool)
	defer close(die)

	laddr, err := net.ResolveUDPAddr("udp", c.Localaddr)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}

	rbuf := make([]byte, 2048)
	sessions := make(map[string]*relaySession)
	var lock sync.Mutex

	go func() {
		ticker := time.NewTicker(time.Second * 30)
		for {
			select {
			case <-die:
				return
			case <-ticker.C:
				lock.Lock()
				for k, v := range sessions {
					if v.live {
						v.live = false
					} else {
						v.Close()
						delete(sessions, k)
					}
				}
				lock.Unlock()
			}
		}
	}()

	for {
		n, addr, err := conn.ReadFrom(rbuf)
		if err != nil {
			log.Println(err)
			return
		}
		if n < 3 || rbuf[2] != 0 {
			continue
		}
		var host string
		var port int
		var data []byte
		if c.UdpOverTCP {
			host, port, data = ss.ParseAddr(rbuf[3:n])
		}
		addrstr := addr.String()
		lock.Lock()
		sess, ok := sessions[addrstr]
		lock.Unlock()
		if ok {
			sess.live = true
			if c.UdpOverTCP {
				sess.conn.Write(data)
			} else {
				sess.conn.Write(rbuf[3:n])
			}
			continue
		}
		var rconn net.Conn
		if c.UdpOverTCP {
			if len(host) == 0 {
				continue
			}
			rconn, err = ss.DialUDPOverTCP(net.JoinHostPort(host, strconv.Itoa(port)), c.Remoteaddr, c)
			if err != nil {
				continue
			}
			rconn.Write(data)
			header := make([]byte, n-len(data))
			copy(header, rbuf)
			sess = &relaySession{conn: rconn, live: true, from: addr.(*net.UDPAddr), die: make(chan bool), header: header}
		} else {
			rconn, err = net.Dial("udp", c.Remoteaddr)
			if err != nil {
				rconn.Close()
				continue
			}
			rconn = ss.NewUDPConn(rconn.(*net.UDPConn), c)
			rconn.Write(rbuf[3:n])
			sess = &relaySession{conn: rconn, live: true, from: addr.(*net.UDPAddr), die: make(chan bool), header: []byte{0, 0, 0}}
		}
		lock.Lock()
		sessions[addrstr] = sess
		lock.Unlock()
		go func(sess *relaySession) {
			defer sess.Close()
			b := make([]byte, 2048)
			copy(b, sess.header)
			for {
				n, err := sess.conn.Read(b[len(sess.header):])
				if err != nil {
					return
				}
				select {
				case <-sess.die:
					return
				default:
				}
				_, err = conn.WriteTo(b[:n+len(sess.header)], sess.from)
				if err != nil {
					return
				}
			}
		}(sess)
	}
}
