package ss

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type statServer struct {
	startTime        time.Time
	reloadTime       time.Time
	connections      int32
	totalConnections int64
	peakConnections  int32
	totalReadBytes   int64
	totalWritBytes   int64
	readSnap         int64
	writSnap         int64
	connSnap         int64
	readSpeed        int32
	writSpeed        int32
	connErrNum       int32
	tracker          *ConnTracker
}

type statConn struct {
	Conn
	s      *statServer
	record *ConnRecord
	once   sync.Once
}

// StatConn is the exported alias for type assertions.
type StatConn = statConn

func (c *statConn) Unwrap() net.Conn { return c.Conn }

func newStatConn(conn Conn, s *statServer) *statConn {
	atomic.AddInt64(&s.totalConnections, 1)
	cur := atomic.AddInt32(&s.connections, 1)
	for {
		peak := atomic.LoadInt32(&s.peakConnections)
		if cur <= peak {
			break
		}
		if atomic.CompareAndSwapInt32(&s.peakConnections, peak, cur) {
			break
		}
	}
	srcAddr := ""
	if ra := conn.RemoteAddr(); ra != nil {
		srcAddr = ra.String()
	}
	dstAddr := ""
	if dst := conn.GetDst(); dst != nil {
		dstAddr = dst.String()
	}
	host := conn.GetHost()
	if s.tracker == nil {
		s.tracker = newConnTracker()
	}
	rec := s.tracker.Register(srcAddr, dstAddr, host)
	return &statConn{Conn: conn, s: s, record: rec}
}

func (conn *statConn) Close() error {
	conn.once.Do(func() {
		atomic.AddInt32(&conn.s.connections, -1)
		if conn.record != nil && conn.s.tracker != nil {
			conn.s.tracker.Unregister(conn.record)
		}
	})
	return conn.Conn.Close()
}

func (conn *statConn) Read(b []byte) (n int, err error) {
	defer func() {
		if n > 0 {
			atomic.AddInt64(&conn.s.totalReadBytes, int64(n))
			if conn.record != nil {
				conn.record.addRead(n)
			}
		}
	}()
	n, err = conn.Conn.Read(b)
	return
}

func (conn *statConn) Write(b []byte) (n int, err error) {
	defer func() {
		if n > 0 {
			atomic.AddInt64(&conn.s.totalWritBytes, int64(n))
			if conn.record != nil {
				conn.record.addWrite(n)
			}
		}
	}()
	n, err = conn.Conn.Write(b)
	return
}

// Snap captures rate snapshots and returns the delta since last snap.
// Caller is expected to call this periodically (e.g. every 2s).
func (s *statServer) Snap() (readRate, writRate, connRate int64) {
	readBytes := atomic.LoadInt64(&s.totalReadBytes)
	writBytes := atomic.LoadInt64(&s.totalWritBytes)
	conns := atomic.LoadInt64(&s.totalConnections)

	readRate = readBytes - atomic.SwapInt64(&s.readSnap, readBytes)
	writRate = writBytes - atomic.SwapInt64(&s.writSnap, writBytes)
	connRate = conns - atomic.SwapInt64(&s.connSnap, conns)
	return
}

// GetRecord returns the ConnRecord for this connection.
func (conn *statConn) GetRecord() *ConnRecord { return conn.record }

// GetTracker returns the ConnTracker for this config.
func (c *Config) GetTracker() *ConnTracker {
	if c.stat != nil {
		return c.stat.tracker
	}
	return nil
}

func (conn *statConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	defer func() {
		if n > 0 {
			atomic.AddInt64(&conn.s.totalWritBytes, int64(n))
			if conn.record != nil {
				conn.record.addWrite(n)
			}
		}
	}()
	n, err = conn.Conn.WriteBuffers(bufs)
	return
}
