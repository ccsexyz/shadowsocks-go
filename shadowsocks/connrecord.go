package ss

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ConnRecord holds metadata for a single proxied connection.
type ConnRecord struct {
	ID           uint64     `json:"id"`
	SrcAddr      string     `json:"srcAddr"`
	DstAddr      string     `json:"dstAddr"`
	Host         string     `json:"host"`
	StartTime    time.Time  `json:"startTime"`
	EndTime      *time.Time `json:"endTime,omitempty"`
	ReadBytes    int64      `json:"readBytes"`
	WritBytes    int64      `json:"writBytes"`
	PairedID     uint64     `json:"pairedID"`
	Samples      []BwSample `json:"samples,omitempty"`
	LastActivity int64      `json:"lastActive"` // UnixNano of last read/write
}

// ConnTracker tracks active and recently-closed connections for one Config.
type ConnTracker struct {
	mu         sync.Mutex
	active     map[uint64]*ConnRecord
	history    []*ConnRecord
	historyPos int
	historyCap int
	nextID     uint64
}

const (
	defaultHistoryCap = 200
	maxBwSamples      = 60 // 60 seconds of per-second bandwidth data
)

// BwSample holds read/write bytes for one second.
type BwSample struct {
	Read  int64 `json:"r"`
	Write int64 `json:"w"`
}

func newConnTracker() *ConnTracker {
	return &ConnTracker{
		active:     make(map[uint64]*ConnRecord),
		history:    make([]*ConnRecord, 0, defaultHistoryCap),
		historyCap: defaultHistoryCap,
	}
}

// Register creates a new ConnRecord and adds it to the active set.
func (t *ConnTracker) Register(srcAddr, dstAddr, host string) *ConnRecord {
	t.mu.Lock()
	id := t.nextID
	t.nextID++
	now := time.Now()
	rec := &ConnRecord{
		ID:           id,
		SrcAddr:      srcAddr,
		DstAddr:      dstAddr,
		Host:         host,
		StartTime:    now,
		LastActivity: now.UnixNano(),
	}
	t.active[id] = rec
	t.mu.Unlock()
	return rec
}

// Unregister moves a record from active to history on connection close.
func (t *ConnTracker) Unregister(rec *ConnRecord) {
	t.mu.Lock()
	delete(t.active, rec.ID)
	now := time.Now()
	rec.EndTime = &now

	if len(t.history) < t.historyCap {
		t.history = append(t.history, rec)
	} else {
		t.history[t.historyPos] = rec
		t.historyPos = (t.historyPos + 1) % t.historyCap
	}
	t.mu.Unlock()
}

// Active returns a snapshot of currently active connections.
func (t *ConnTracker) Active() []*ConnRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]*ConnRecord, 0, len(t.active))
	for _, r := range t.active {
		out = append(out, r)
	}
	return out
}

// History returns a snapshot of recently closed connections (newest first).
func (t *ConnTracker) History() []*ConnRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := len(t.history)
	out := make([]*ConnRecord, 0, n)
	if n < t.historyCap {
		// buffer not yet full; return reversed
		for i := n - 1; i >= 0; i-- {
			out = append(out, t.history[i])
		}
	} else {
		// ring buffer is full; walk backward from current position
		for i := 0; i < n; i++ {
			idx := (t.historyPos - 1 - i + n) % n
			out = append(out, t.history[idx])
		}
	}
	return out
}

// addRead adds read bytes to the record (called from statConn.Read).
func (r *ConnRecord) addRead(n int) {
	if n > 0 {
		atomic.AddInt64(&r.ReadBytes, int64(n))
		atomic.StoreInt64(&r.LastActivity, time.Now().UnixNano())
		r.bwSample(int64(n), 0)
	}
}

// addWrite adds written bytes to the record (called from statConn.Write).
func (r *ConnRecord) addWrite(n int) {
	if n > 0 {
		atomic.AddInt64(&r.WritBytes, int64(n))
		atomic.StoreInt64(&r.LastActivity, time.Now().UnixNano())
		r.bwSample(0, int64(n))
	}
}

// bwSample records per-second bandwidth data.
func (r *ConnRecord) bwSample(rn, wn int64) {
	sec := int(time.Since(r.StartTime).Seconds())
	if sec < 0 {
		return
	}
	if sec >= maxBwSamples {
		sec = maxBwSamples - 1
	}
	// lazily allocate samples
	if r.Samples == nil {
		r.Samples = make([]BwSample, maxBwSamples)
	}
	atomic.AddInt64(&r.Samples[sec].Read, rn)
	atomic.AddInt64(&r.Samples[sec].Write, wn)
}

// TrackOutbound creates a paired outbound record and returns a net.Conn wrapper that tracks bytes.
// inboundRec is the record for the incoming connection that triggered this outbound dial.
func (t *ConnTracker) TrackOutbound(conn net.Conn, inboundRec *ConnRecord, dstAddr string) net.Conn {
	if t == nil || inboundRec == nil {
		return conn
	}
	t.mu.Lock()
	id := t.nextID
	t.nextID++
	now := time.Now()
	rec := &ConnRecord{
		ID:           id,
		SrcAddr:      "server",
		DstAddr:      dstAddr,
		StartTime:    now,
		LastActivity: now.UnixNano(),
		PairedID:     inboundRec.ID,
	}
	t.active[id] = rec
	inboundRec.PairedID = id
	t.mu.Unlock()
	return &trackedOutConn{Conn: conn, record: rec, tracker: t}
}

// trackedOutConn wraps a net.Conn, updating a ConnRecord with bytes read/written.
type trackedOutConn struct {
	net.Conn
	record  *ConnRecord
	tracker *ConnTracker
}

func (c *trackedOutConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.record.addRead(n)
	return n, err
}

func (c *trackedOutConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.record.addWrite(n)
	return n, err
}

func (c *trackedOutConn) Close() error {
	if c.tracker != nil && c.record != nil {
		c.tracker.Unregister(c.record)
	}
	return c.Conn.Close()
}
