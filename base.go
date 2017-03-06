package main

import (
	"log"
	"net"
	"sync"
	"time"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

func RunTCPServer(address string, c *ss.Config,
	listen func(string, *ss.Config) (net.Listener, error),
	handler func(net.Conn, *ss.Config)) {
	ss.CheckConfig(c)
	lis, err := listen(address, c)
	if err != nil {
		log.Fatal(err)
	}
	defer lis.Close()
	for {
		conn, err := lis.Accept()
		if err != nil {
			return
		}
		go handler(conn, c)
	}
}

type udpSession struct {
	conn   net.Conn
	live   bool
	from   *net.UDPAddr
	die    chan bool
	clean  func()
	header []byte
}

func (sess *udpSession) Close() {
	select {
	case <-sess.die:
	default:
		sess.conn.Close()
		close(sess.die)
		if sess.clean != nil {
			sess.clean()
		}
	}
}

func sessionsCleaner(sessions map[string]*udpSession, lock *sync.Mutex, die chan bool, d time.Duration) {
	ticker := time.NewTicker(d)
	for {
		select {
		case <-die:
			return
		case <-ticker.C:
			var closeSessions []*udpSession
			lock.Lock()
			for k, v := range sessions {
				if v.live {
					v.live = false
				} else {
					delete(sessions, k)
					closeSessions = append(closeSessions, v)
				}
			}
			lock.Unlock()
			for _, v := range closeSessions {
				v.Close()
			}
		}
	}
}

func RunUDPServer(conn net.PacketConn, check func([]byte) bool, handle func(*udpSession, []byte),
	create func([]byte) (net.Conn, func(), []byte, error)) {
	defer conn.Close()
	die := make(chan bool)
	defer close(die)
	rbuf := make([]byte, 2048)
	sessions := make(map[string]*udpSession)
	var lock sync.Mutex

	go sessionsCleaner(sessions, &lock, die, time.Minute)

	for {
		n, addr, err := conn.ReadFrom(rbuf)
		if err != nil {
			return
		}
		if check != nil && !check(rbuf[:n]) {
			continue
		}
		addrstr := addr.String()
		lock.Lock()
		sess, ok := sessions[addrstr]
		lock.Unlock()
		if ok {
			sess.live = true
			if handle != nil {
				handle(sess, rbuf[:n])
			}
		} else {
			if create != nil {
				rconn, clean, header, err := create(rbuf[:n])
				if err != nil {
					log.Println(err)
					continue
				}
				if rconn == nil {
					continue
				}
				sess = &udpSession{conn: rconn, live: true, from: addr.(*net.UDPAddr), header: header, die: make(chan bool), clean: clean}
				lock.Lock()
				sessions[addrstr] = sess
				lock.Unlock()
				go func(sess *udpSession) {
					defer sess.Close()
					buf := make([]byte, 2048)
					hdrlen := len(sess.header)
					copy(buf, sess.header)
					sess.header = nil
					for {
						n, err := sess.conn.Read(buf[hdrlen:])
						if err != nil {
							return
						}
						_, err = conn.WriteTo(buf[:hdrlen+n], sess.from)
					}
				}(sess)
			}
		}
	}
}
