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
	configIndex      int
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

	// reject reason counters
	rejectDecryptFail      int64
	rejectTimestampExpired int64
	rejectReplay           int64
	rejectCipherMismatch   int64
	rejectParseFail        int64
	rejectOther            int64

	// per-method traffic counters
	methodMu    sync.RWMutex
	methodStats map[string]*methodStat

	// per-target aggregation
	targetTracker *TargetTracker
}

type methodStat struct {
	ReadBytes int64 `json:"readBytes"`
	WritBytes int64 `json:"writBytes"`
	ConnCount int64 `json:"connCount"`
}

type statConn struct {
	Conn
	s      *statServer
	record *ConnRecord
	method string
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
	method := ""
	if cfg := conn.GetCfg(); cfg != nil {
		method = cfg.Method
	}
	if method != "" {
		s.addMethodConn(method)
		if s.targetTracker == nil {
			s.targetTracker = &TargetTracker{targets: make(map[string]*TargetStats)}
		}
		s.targetTracker.addConn(dstAddr, host)
	}
	if s.configIndex >= 0 {
		ssePublishIndex("connection_opened", s.configIndex, map[string]any{
			"configIndex": s.configIndex,
			"connId":      rec.ID,
		})
	}
	return &statConn{Conn: conn, s: s, record: rec, method: method}
}

func (conn *statConn) Close() error {
	conn.once.Do(func() {
		atomic.AddInt32(&conn.s.connections, -1)
		if conn.record != nil && conn.s.tracker != nil {
			conn.s.tracker.Unregister(conn.record)
		}
		if conn.record != nil && conn.s.targetTracker != nil {
			conn.s.targetTracker.addBytes(conn.record.DstAddr, conn.record.ReadBytes, conn.record.WritBytes)
			conn.s.targetTracker.updateLastSeen(conn.record.DstAddr)
		}
		if conn.s.configIndex >= 0 {
			ssePublishIndex("connection_closed", conn.s.configIndex, map[string]any{
				"configIndex": conn.s.configIndex,
				"connId":      conn.record.ID,
			})
		}
	})
	return conn.Conn.Close()
}

func (conn *statConn) Read(b []byte) (n int, err error) {
	defer func() {
		if n > 0 {
			atomic.AddInt64(&conn.s.totalReadBytes, int64(n))
			if conn.method != "" {
				conn.s.addMethodReadBytes(conn.method, int64(n))
			}
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
			if conn.method != "" {
				conn.s.addMethodWritBytes(conn.method, int64(n))
			}
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
	if s := c.getStat(); s != nil {
		return s.tracker
	}
	return nil
}

func (s *statServer) incReject(reason string) {
	switch reason {
	case "decrypt":
		atomic.AddInt64(&s.rejectDecryptFail, 1)
	case "timestamp":
		atomic.AddInt64(&s.rejectTimestampExpired, 1)
	case "replay":
		atomic.AddInt64(&s.rejectReplay, 1)
	case "cipher":
		atomic.AddInt64(&s.rejectCipherMismatch, 1)
	case "parse":
		atomic.AddInt64(&s.rejectParseFail, 1)
	default:
		atomic.AddInt64(&s.rejectOther, 1)
	}
	if s.configIndex >= 0 {
		ssePublishIndex("reject_updated", s.configIndex, map[string]any{
			"configIndex": s.configIndex,
			"counters":    s.getRejectCounters(),
		})
	}
}

// RejectCounters holds the per-reason reject counts.
type RejectCounters struct {
	DecryptFail      int64 `json:"decryptFail"`
	TimestampExpired int64 `json:"timestampExpired"`
	Replay           int64 `json:"replay"`
	CipherMismatch   int64 `json:"cipherMismatch"`
	ParseFail        int64 `json:"parseFail"`
	Other            int64 `json:"other"`
}

func (s *statServer) getRejectCounters() RejectCounters {
	return RejectCounters{
		DecryptFail:      atomic.LoadInt64(&s.rejectDecryptFail),
		TimestampExpired: atomic.LoadInt64(&s.rejectTimestampExpired),
		Replay:           atomic.LoadInt64(&s.rejectReplay),
		CipherMismatch:   atomic.LoadInt64(&s.rejectCipherMismatch),
		ParseFail:        atomic.LoadInt64(&s.rejectParseFail),
		Other:            atomic.LoadInt64(&s.rejectOther),
	}
}

func (s *statServer) addMethodReadBytes(method string, n int64) {
	s.methodMu.Lock()
	ms := s.methodStats[method]
	if ms == nil {
		ms = &methodStat{}
		s.methodStats[method] = ms
	}
	atomic.AddInt64(&ms.ReadBytes, n)
	s.methodMu.Unlock()
}

func (s *statServer) addMethodWritBytes(method string, n int64) {
	s.methodMu.Lock()
	ms := s.methodStats[method]
	if ms == nil {
		ms = &methodStat{}
		s.methodStats[method] = ms
	}
	atomic.AddInt64(&ms.WritBytes, n)
	s.methodMu.Unlock()
}

func (s *statServer) addMethodConn(method string) {
	s.methodMu.Lock()
	ms := s.methodStats[method]
	if ms == nil {
		ms = &methodStat{}
		s.methodStats[method] = ms
	}
	atomic.AddInt64(&ms.ConnCount, 1)
	s.methodMu.Unlock()
}

func (s *statServer) getMethodStats() map[string]*methodStat {
	s.methodMu.RLock()
	defer s.methodMu.RUnlock()
	out := make(map[string]*methodStat, len(s.methodStats))
	for k, v := range s.methodStats {
		out[k] = &methodStat{
			ReadBytes: atomic.LoadInt64(&v.ReadBytes),
			WritBytes: atomic.LoadInt64(&v.WritBytes),
			ConnCount: atomic.LoadInt64(&v.ConnCount),
		}
	}
	return out
}

func (conn *statConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	defer func() {
		if n > 0 {
			atomic.AddInt64(&conn.s.totalWritBytes, int64(n))
			if conn.method != "" {
				conn.s.addMethodWritBytes(conn.method, int64(n))
			}
			if conn.record != nil {
				conn.record.addWrite(n)
			}
		}
	}()
	n, err = conn.Conn.WriteBuffers(bufs)
	return
}
