package utils

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// Conn is the project-wide connection interface.
type Conn interface {
	Read(buf []byte, pool *BufPool) (segs [][]byte, err error)
	Write(bufs ...[]byte) (n int, err error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// UDPConn is the union set of net.Conn and net.PacketConn
type UDPConn interface {
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	ReadFrom(b []byte) (n int, addr net.Addr, err error)
	WriteTo(b []byte, addr net.Addr) (n int, err error)
}

// simpleBuf is a single-segment Buffer stored by value in SubConn.bufs
// to avoid heap allocation via interface boxing.
type simpleBuf struct {
	data  []byte
	full  []byte // original full buf for PutBuf on Release
	bufs0 [1][]byte
}

func (s *simpleBuf) Buffers() [][]byte {
	s.bufs0[0] = s.data
	return s.bufs0[:]
}
func (s *simpleBuf) Len() int { return len(s.data) }

func (s *simpleBuf) Release() { PutBuf(s.full) }

// SubConn is the child connection of a net.PacketConn
type SubConn struct {
	die    chan bool
	pdie   chan bool
	lock   sync.Mutex
	sigch  chan int
	rbuf   []byte
	rbsig  chan struct{}
	bufs   []simpleBuf
	bufCap int
	net.PacketConn
	connsMap *sync.Map
	mtu      int
	raddr    net.Addr
	rtime    time.Time
	rtimer   *time.Timer
}

const defaultBufCap = 64

func newSubConn(c net.PacketConn, ctx *UDPServerCtx, raddr net.Addr) *SubConn {
	return &SubConn{
		die:        make(chan bool),
		pdie:       ctx.die,
		sigch:      make(chan int, 1),
		rbsig:      make(chan struct{}, 1),
		PacketConn: c,
		connsMap:   ctx.connsMap,
		mtu:        ctx.Mtu,
		raddr:      raddr,
		rtimer:     time.NewTimer(time.Hour),
		bufCap:     defaultBufCap,
	}
}

func (conn *SubConn) input(b []byte) {
	buf := GetBuf(len(b))
	n := copy(buf, b)
	buffer := simpleBuf{data: buf[:n], full: buf}

	conn.lock.Lock()
	if conn.rbuf != nil {
		n := copy(conn.rbuf, b)
		conn.rbuf = nil
		buffer.Release()
		conn.lock.Unlock()
		select {
		case conn.sigch <- n:
		default:
		}
		return
	}

	if len(conn.bufs) >= conn.bufCap {
		conn.bufs[0].Release()
		conn.bufs = conn.bufs[1:]
	}
	conn.bufs = append(conn.bufs, buffer)
	conn.lock.Unlock()

	select {
	case conn.rbsig <- struct{}{}:
	default:
	}
}

func (conn *SubConn) Close() error {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	select {
	case <-conn.die:
	default:
		close(conn.die)
	}
	if conn.connsMap != nil && conn.raddr != nil {
		// Conditional delete: a new SubConn for the same remote address may
		// have replaced this one in the map while this session was winding
		// down; deleting by key alone would orphan the new session.
		conn.connsMap.CompareAndDelete(conn.raddr.String(), any(conn))
	}
	for i := range conn.bufs {
		conn.bufs[i].Release()
	}
	conn.bufs = nil
	if conn.rtimer != nil {
		conn.rtimer.Stop()
	}
	select {
	case <-conn.rbsig:
	default:
	}
	return nil
}

func (conn *SubConn) RemoteAddr() net.Addr {
	return conn.raddr
}

func (conn *SubConn) Read(b []byte) (n int, err error) {
	conn.lock.Lock()
	if len(conn.bufs) > 0 {
		sb := conn.bufs[0]
		conn.bufs = conn.bufs[1:]
		conn.lock.Unlock()
		n = copy(b, sb.Buffers()[0])
		sb.Release()
		return
	}
	conn.rbuf = b
	conn.lock.Unlock()
	var rtch <-chan time.Time
	now := time.Now()
	if !conn.rtime.Equal(time.Time{}) {
		if now.After(conn.rtime) {
			err = fmt.Errorf("timeout")
			return
		}
		if !conn.rtimer.Stop() {
			select {
			case <-conn.rtimer.C:
			default:
			}
		}
		conn.rtimer.Reset(conn.rtime.Sub(now))
		rtch = conn.rtimer.C
	}
	defer func() {
		conn.lock.Lock()
		conn.rbuf = nil
		conn.lock.Unlock()
	}()
	select {
	case <-rtch:
		err = fmt.Errorf("timeout")
		return
	case <-conn.die:
		err = fmt.Errorf("closed connection")
		return
	case <-conn.pdie:
		err = fmt.Errorf("closed PacketConn")
		return
	case n = <-conn.sigch:
	}
	return
}

func (conn *SubConn) ReadBuffer() ([][]byte, error) {
	for {
		conn.lock.Lock()
		if len(conn.bufs) > 0 {
			b := &conn.bufs[0]
			v := *b
			conn.bufs = conn.bufs[1:]
			conn.lock.Unlock()
			return [][]byte{v.data}, nil
		}
		conn.lock.Unlock()

		// input() appends to bufs before signaling rbsig, so by the time a
		// signal is observable the queue check above has already re-run; do
		// NOT drain the signal here — consuming it between the queue check
		// and the wait below would lose the wakeup for data already queued.
		select {
		case <-conn.rbsig:
		case <-conn.die:
			return nil, fmt.Errorf("closed connection")
		case <-conn.pdie:
			return nil, fmt.Errorf("closed PacketConn")
		}
	}
}

func (conn *SubConn) Write(b []byte) (n int, err error) {
	return conn.PacketConn.WriteTo(b, conn.raddr)
}

func (conn *SubConn) SetReadDeadline(t time.Time) error {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	conn.rtime = t
	return nil
}

func (conn *SubConn) WriteBuffer(buf [][]byte) (n int, err error) {
	for _, seg := range buf {
		n += len(seg)
	}
	flat := GetBuf(n)
	defer PutBuf(flat)
	off := 0
	for _, seg := range buf {
		off += copy(flat[off:], seg)
	}
	_, err = conn.Write(flat[:n])
	return
}
