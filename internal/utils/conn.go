package utils

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// UDPConn is the union set of net.Conn and net.PacketConn
type UDPConn interface {
	// Read reads data from the connection.
	// Read can be made to time out and return an Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetReadDeadline.
	Read(b []byte) (n int, err error)

	// Write writes data to the connection.
	// Write can be made to time out and return an Error with Timeout() == true
	// after a fixed time limit; see SetDeadline and SetWriteDeadline.
	Write(b []byte) (n int, err error)

	// Close closes the connection.
	// Any blocked Read or Write operations will be unblocked and return errors.
	Close() error

	// LocalAddr returns the local network address.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr

	// SetDeadline sets the read and write deadlines associated
	// with the connection. It is equivalent to calling both
	// SetReadDeadline and SetWriteDeadline.
	//
	// A deadline is an absolute time after which I/O operations
	// fail with a timeout (see type Error) instead of
	// blocking. The deadline applies to all future and pending
	// I/O, not just the immediately following call to Read or
	// Write. After a deadline has been exceeded, the connection
	// can be refreshed by setting a deadline in the future.
	//
	// An idle timeout can be implemented by repeatedly extending
	// the deadline after successful Read or Write calls.
	//
	// A zero value for t means I/O operations will not time out.
	SetDeadline(t time.Time) error

	// SetReadDeadline sets the deadline for future Read calls
	// and any currently-blocked Read call.
	// A zero value for t means Read will not time out.
	SetReadDeadline(t time.Time) error

	// SetWriteDeadline sets the deadline for future Write calls
	// and any currently-blocked Write call.
	// Even if write times out, it may return n > 0, indicating that
	// some of the data was successfully written.
	// A zero value for t means Write will not time out.
	SetWriteDeadline(t time.Time) error

	// ReadFrom reads a packet from the connection,
	// copying the payload into b. It returns the number of
	// bytes copied into b and the return address that
	// was on the packet.
	// ReadFrom can be made to time out and return
	// an Error with Timeout() == true after a fixed time limit;
	// see SetDeadline and SetReadDeadline.
	ReadFrom(b []byte) (n int, addr net.Addr, err error)

	// WriteTo writes a packet with payload b to addr.
	// WriteTo can be made to time out and return
	// an Error with Timeout() == true after a fixed time limit;
	// see SetDeadline and SetWriteDeadline.
	// On packet-oriented connections, write timeouts are rare.
	WriteTo(b []byte, addr net.Addr) (n int, err error)
}

// Conn represents a net.Conn that implement WriteBuffers method
// WriteBuffers can write serveral buffers at a time
type Conn interface {
	net.Conn
	WriteBuffers([][]byte) (int, error)
}

// UtilsConn is a net.Conn that implement the interface Conn
type UtilsConn struct {
	net.Conn
}

// GetTCPConn try to get the underlying TCPConn
func (conn *UtilsConn) GetTCPConn() (t *net.TCPConn, ok bool) {
	t, ok = conn.Conn.(*net.TCPConn)
	return
}

// WriteBuffers can send serveral buffers at a time
func (conn *UtilsConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	buffers := net.Buffers(bufs)
	var n2 int64
	n2, err = buffers.WriteTo(conn.Conn)
	n = int(n2)
	return
}

// DialTCP calls net.DialTCP and returns *UtilsConn
func DialTCP(network string, address string, ctx context.Context) (conn *UtilsConn, err error) {
	var d net.Dialer
	netconn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return
	}

	conn = &UtilsConn{Conn: netconn}
	return
}

// NewConn returns *UtilsConn from net.Conn
func NewConn(conn net.Conn) *UtilsConn {
	return &UtilsConn{Conn: conn}
}

type tmpBuf struct {
	buf []byte
	off int
}

// SubConn is the child connection of a net.PacketConn
type SubConn struct {
	die     chan bool
	pdie    chan bool
	lock    sync.Mutex
	sigch   chan int
	rbuf    []byte
	tmpbufs []tmpBuf
	net.PacketConn
	connsMap *sync.Map
	mtu      int
	raddr    net.Addr
	rtime    time.Time
}

func newSubConn(c net.PacketConn, ctx *UDPServerCtx, raddr net.Addr) *SubConn {
	return &SubConn{
		die:        make(chan bool),
		pdie:       ctx.die,
		sigch:      make(chan int),
		PacketConn: c,
		connsMap:   ctx.connsMap,
		mtu:        ctx.Mtu,
		raddr:      raddr,
	}
}

func (conn *SubConn) input(b []byte) {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	var n int
	if conn.rbuf != nil {
		n = copy(conn.rbuf, b)
		conn.rbuf = nil
		conn.sigch <- n
		return
	}
	var tmpbuf tmpBuf
	tmpbuf.buf = GetBuf(conn.mtu)
	tmpbuf.off = copy(tmpbuf.buf, b)
	conn.tmpbufs = append(conn.tmpbufs, tmpbuf)
}

// Close close the connection and delete it from connsMap
func (conn *SubConn) Close() error {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	select {
	case <-conn.die:
	default:
		close(conn.die)
	}
	if conn.connsMap != nil && conn.raddr != nil {
		conn.connsMap.Delete(conn.raddr.String())
	}
	if len(conn.tmpbufs) != 0 {
		for _, tmpbuf := range conn.tmpbufs {
			PutBuf(tmpbuf.buf)
		}
		conn.tmpbufs = nil
	}
	return nil
}

// RemoteAddr return the address of peer
func (conn *SubConn) RemoteAddr() net.Addr {
	return conn.raddr
}

func (conn *SubConn) Read(b []byte) (n int, err error) {
	conn.lock.Lock()
	if len(conn.tmpbufs) != 0 {
		tmpbuf := conn.tmpbufs[0]
		conn.tmpbufs = conn.tmpbufs[1:]
		n = copy(b, tmpbuf.buf[:tmpbuf.off])
		conn.lock.Unlock()
		PutBuf(tmpbuf.buf)
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
		rtimer := time.NewTimer(conn.rtime.Sub(now))
		rtch = rtimer.C
		defer rtimer.Stop()
	}
	// defer func() {
	// 	conn.lock.Lock()
	// 	defer conn.lock.Unlock()
	// 	conn.rbuf = nil
	// }()
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

func (conn *SubConn) Write(b []byte) (n int, err error) {
	return conn.PacketConn.WriteTo(b, conn.raddr)
}

// SetReadDeadline set the dealdine of read
func (conn *SubConn) SetReadDeadline(t time.Time) error {
	conn.lock.Lock()
	defer conn.lock.Unlock()
	conn.rtime = t
	return nil
}

// WriteBuffers directly copy all buffers into a larger buf and send it
func (conn *SubConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	for _, v := range bufs {
		n += len(v)
	}
	buf := GetBuf(n)
	defer PutBuf(buf)
	n = 0
	for _, v := range bufs {
		n += copy(buf[n:], v)
	}
	n, err = conn.Write(buf)
	return
}
