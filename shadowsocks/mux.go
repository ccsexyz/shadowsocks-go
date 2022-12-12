package ss

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/ccsexyz/mux"
)

func init() {
	StoreServiceHandler(muxaddr, muxAcceptHandler)
}

func muxAcceptHandler(conn Conn, lis *listener) (c Conn) {
	if lis.c.Mux == false {
		return
	}
	mux, err := mux.NewMux(conn)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Time{})
	c = nilConn
	go func() {
		defer mux.Close()
		for {
			muxconn, err := mux.AcceptMux()
			if err != nil {
				return
			}
			go lis.muxConnHandler(newTCPConn2(muxconn, lis.c))
		}
	}()
	return
}

func (lis *listener) muxConnHandler(conn Conn) {
	buf := make([]byte, 512)
	var err error
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()
	_, err = io.ReadFull(conn, buf[:1])
	if err != nil {
		return
	}
	addrlen := int(buf[0])
	_, err = io.ReadFull(conn, buf[:addrlen])
	if err != nil {
		return
	}
	var dst DstAddr
	dst.host, dst.port, err = net.SplitHostPort(string(buf[:addrlen]))
	if err != nil {
		return
	}
	conn.SetDst(&dst)
	select {
	case lis.connch <- conn:
	case <-lis.die:
		conn.Close()
	}
	conn = nil
}

func DialMux(target string, c *Config) (conn Conn, err error) {
	conn, err = c.muxDialer.Dial(c)
	if err != nil {
		return
	}
	buf := make([]byte, len(target)+1)
	buf[0] = byte(len(target))
	copy(buf[1:], []byte(target))
	buf = buf[:1+int(buf[0])]
	_, err = conn.Write(buf)
	if err != nil {
		conn.Close()
		conn = nil
	}
	return
}

type MuxDialer struct {
	lock    sync.Mutex
	muxs    []*muxDialerInfo
	timeout time.Duration
}

type muxDialerInfo struct {
	mux *mux.Mux
	ts  time.Time
}

func (md *MuxDialer) Dial(c *Config) (conn Conn, err error) {
	md.lock.Lock()
	muxs := make([]*muxDialerInfo, len(md.muxs))
	copy(muxs, md.muxs)
	timeout := md.timeout * 1414 / 1000
	md.lock.Unlock()
	n := len(muxs)
	die := make(chan bool)
	errch := make(chan error, n)
	expirech := make(chan error, n)
	connch := make(chan Conn)
	timeoutch := time.After(timeout)
	start := time.Now()
	for _, v := range muxs {
		go func(v *muxDialerInfo) {
			if start.After(v.ts) {
				if v.mux.NumOfConns() == 0 {
					v.mux.Close()
					md.lock.Lock()
					nmuxs := len(md.muxs)
					for i, m := range md.muxs {
						if m == v {
							md.muxs[i] = md.muxs[nmuxs-1]
							md.muxs = md.muxs[:nmuxs-1]
							break
						}
					}
					md.lock.Unlock()
				}
				select {
				case <-die:
				case expirech <- fmt.Errorf("connection %v->%v is expired", v.mux.LocalAddr(), v.mux.RemoteAddr()):
				}
				return
			}
			var mconn net.Conn
			mconn, err = v.mux.Dial()
			if err != nil {
				v.mux.Close()
				md.lock.Lock()
				nmuxs := len(md.muxs)
				for i, m := range md.muxs {
					if m == v {
						md.muxs[i] = md.muxs[nmuxs-1]
						md.muxs = md.muxs[:nmuxs-1]
						break
					}
				}
				md.lock.Unlock()
				select {
				case <-die:
				case errch <- err:
				}
				return
			}
			select {
			case connch <- newTCPConn2(mconn, c):
			case <-die:
				mconn.Close()
			}
		}(v)
	}
	f := func() {
		ssconn, err := DialSSWithOptions(&DialOptions{
			RawHeader: []byte{typeMux},
			C:         c,
		})
		if err == nil {
			var smux *mux.Mux
			smux, err = mux.NewMux(ssconn)
			if err == nil {
				var nconn net.Conn
				nconn, err = smux.Dial()
				if err == nil {
					mconn := newTCPConn2(nconn, c)
					select {
					case <-die:
					case connch <- mconn:
						md.lock.Lock()
						md.muxs = append(md.muxs, &muxDialerInfo{mux: smux, ts: time.Now().Add(time.Second * 60)})
						md.lock.Unlock()
						return
					}
					mconn.Close()
				}
				smux.Close()
			}
			ssconn.Close()
		}
		select {
		case <-die:
		case errch <- err:
		}
	}
	fstarted := false
	it := 0
out:
	for {
		select {
		case err = <-errch:
			it++
			if it >= n {
				md.lock.Lock()
				nmuxs := len(md.muxs)
				md.lock.Unlock()
				if nmuxs == 0 && !fstarted {
					n++
					fstarted = true
					go f()
				} else {
					break out
				}
			}
		case err = <-expirech:
			if fstarted {
				n--
			} else {
				fstarted = true
				go f()
			}
		case <-timeoutch:
			if fstarted {
				continue out
			}
			if c.MuxLimit > 0 {
				md.lock.Lock()
				nmuxs := len(md.muxs)
				md.lock.Unlock()
				if nmuxs >= c.MuxLimit {
					break
				}
			}
			n++
			fstarted = true
			go f()
		case conn = <-connch:
			err = nil
			close(die)
			delay := time.Now().Sub(start)
			md.lock.Lock()
			if md.timeout == 0 {
				md.timeout = delay
			} else if delay != 0 {
				md.timeout = (md.timeout*16 + delay) / 17
			}
			md.lock.Unlock()
			break out
		}
	}
	return
}
