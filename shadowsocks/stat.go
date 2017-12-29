package ss

import (
	"sync"
	"sync/atomic"
	"time"
)

type statServer struct {
	startTime      time.Time
	reloadTime     time.Time
	connections    int32
	totalReadBytes int64
	totalWritBytes int64
	readSpeed      int32
	writSpeed      int32
	connErrNum     int32
}

type statConn struct {
	Conn
	s    *statServer
	once sync.Once
}

func newStatConn(conn Conn, s *statServer) *statConn {
	defer atomic.AddInt32(&s.connections, 1)
	return &statConn{Conn: conn, s: s}
}

func (conn *statConn) Close() error {
	conn.once.Do(func() {
		atomic.AddInt32(&conn.s.connections, -1)
	})
	return conn.Conn.Close()
}

func (conn *statConn) Read(b []byte) (n int, err error) {
	defer func() {
		if n == 0 {
			return
		}
		atomic.AddInt64(&conn.s.totalReadBytes, int64(n))
	}()
	n, err = conn.Conn.Read(b)
	return
}

func (conn *statConn) Write(b []byte) (n int, err error) {
	defer func() {
		if n == 0 {
			return
		}
		atomic.AddInt64(&conn.s.totalWritBytes, int64(n))
	}()
	n, err = conn.Conn.Write(b)
	return
}

func (conn *statConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	defer func() {
		if n == 0 {
			return
		}
		atomic.AddInt64(&conn.s.totalWritBytes, int64(n))
	}()
	n, err = conn.Conn.WriteBuffers(bufs)
	return
}
