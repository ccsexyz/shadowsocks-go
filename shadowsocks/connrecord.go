package ss

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
	lastPublish  int64      // UnixNano of last SSE publish (throttle)
}

// ConnTracker tracks active and recently-closed connections for one Config.
type ConnTracker struct {
	mu         sync.Mutex
	active     map[uint64]*ConnRecord
	history    []*ConnRecord
	historyPos int
	historyCap int
	nextID     uint64
	logger     *ConnLogger
}

// SetConnLogger attaches a connection logger for JSON Lines output.
func (t *ConnTracker) SetConnLogger(logPath string) {
	if logPath != "" {
		t.logger = &ConnLogger{}
		if err := t.logger.open(logPath); err != nil {
			t.logger = nil
		}
	}
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

	// SSE: notify subscribers that this connection closed
	b, _ := json.Marshal(rec)
	connEventPublish(rec.ID, "closed", b)

	if t.logger != nil {
		t.logger.write(rec)
	}
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
		r.publishUpdate()
	}
}

// addWrite adds written bytes to the record (called from statConn.Write).
func (r *ConnRecord) addWrite(n int) {
	if n > 0 {
		atomic.AddInt64(&r.WritBytes, int64(n))
		atomic.StoreInt64(&r.LastActivity, time.Now().UnixNano())
		r.bwSample(0, int64(n))
		r.publishUpdate()
	}
}

type connDelta struct {
	ReadBytes    int64 `json:"readBytes"`
	WritBytes    int64 `json:"writBytes"`
	LastActivity int64 `json:"lastActive"`
	SampleIdx    int   `json:"si"`
	SampleR      int64 `json:"sr"`
	SampleW      int64 `json:"sw"`
}

func (r *ConnRecord) publishUpdate() {
	// Throttle: at most once per 500ms
	now := time.Now().UnixNano()
	if now-r.lastPublish < 500_000_000 {
		return
	}
	r.lastPublish = now

	sec := int(time.Since(r.StartTime).Seconds())
	if sec < 0 {
		sec = 0
	}
	if sec >= maxBwSamples {
		sec = maxBwSamples - 1
	}
	d := connDelta{
		ReadBytes: atomic.LoadInt64(&r.ReadBytes),
		WritBytes: atomic.LoadInt64(&r.WritBytes),
		SampleIdx: sec,
	}
	if r.Samples != nil {
		d.SampleR = atomic.LoadInt64(&r.Samples[sec].Read)
		d.SampleW = atomic.LoadInt64(&r.Samples[sec].Write)
	}
	b, _ := json.Marshal(d)
	connEventPublish(r.ID, "update", b)
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

// TargetStats holds aggregated stats for a destination target.
type TargetStats struct {
	Target          string    `json:"target"`
	Host            string    `json:"host,omitempty"`
	TotalReadBytes  int64     `json:"totalReadBytes"`
	TotalWritBytes  int64     `json:"totalWritBytes"`
	ConnectionCount int64     `json:"connectionCount"`
	LastSeen        time.Time `json:"lastSeen"`
}

// TargetTracker maintains per-destination aggregate statistics.
type TargetTracker struct {
	mu      sync.RWMutex
	targets map[string]*TargetStats
}

func (tt *TargetTracker) addConn(dstAddr string, host string) {
	tt.mu.Lock()
	ts := tt.targets[dstAddr]
	if ts == nil {
		ts = &TargetStats{Target: dstAddr, Host: host}
		tt.targets[dstAddr] = ts
	}
	atomic.AddInt64(&ts.ConnectionCount, 1)
	ts.LastSeen = time.Now()
	tt.mu.Unlock()
}

func (tt *TargetTracker) addBytes(dstAddr string, readBytes, writBytes int64) {
	if dstAddr == "" {
		return
	}
	tt.mu.RLock()
	ts := tt.targets[dstAddr]
	tt.mu.RUnlock()
	if ts == nil {
		return
	}
	atomic.AddInt64(&ts.TotalReadBytes, readBytes)
	atomic.AddInt64(&ts.TotalWritBytes, writBytes)
}

func (tt *TargetTracker) updateLastSeen(dstAddr string) {
	tt.mu.RLock()
	ts := tt.targets[dstAddr]
	tt.mu.RUnlock()
	if ts != nil {
		ts.LastSeen = time.Now()
	}
}

// All returns all target stats, sorted by total bytes descending.
func (tt *TargetTracker) All() []*TargetStats {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	out := make([]*TargetStats, 0, len(tt.targets))
	for _, ts := range tt.targets {
		out = append(out, ts)
	}
	// sort by total bytes descending
	for i := 0; i < len(out)-1; i++ {
		for j := i + 1; j < len(out); j++ {
			bi := atomic.LoadInt64(&out[i].TotalReadBytes) + atomic.LoadInt64(&out[i].TotalWritBytes)
			bj := atomic.LoadInt64(&out[j].TotalReadBytes) + atomic.LoadInt64(&out[j].TotalWritBytes)
			if bj > bi {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// Top returns the top N target stats.
func (tt *TargetTracker) Top(n int) []*TargetStats {
	all := tt.All()
	if len(all) > n {
		all = all[:n]
	}
	return all
}

// TopByConns returns the top N targets by connection count.
func (tt *TargetTracker) TopByConns(n int) []*TargetStats {
	tt.mu.RLock()
	defer tt.mu.RUnlock()
	out := make([]*TargetStats, 0, len(tt.targets))
	for _, ts := range tt.targets {
		out = append(out, ts)
	}
	for i := 0; i < len(out)-1; i++ {
		for j := i + 1; j < len(out); j++ {
			if atomic.LoadInt64(&out[j].ConnectionCount) > atomic.LoadInt64(&out[i].ConnectionCount) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ConnLogger writes completed connections as JSON Lines to a daily-rotated file.
type ConnLogger struct {
	mu   sync.Mutex
	dir  string
	file *os.File
	date string
}

func (cl *ConnLogger) open(logPath string) error {
	cl.dir = filepath.Dir(logPath)
	if err := os.MkdirAll(cl.dir, 0755); err != nil {
		return err
	}
	return cl.rotate(time.Now().Format("2006-01-02"))
}

func (cl *ConnLogger) write(rec *ConnRecord) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	today := time.Now().Format("2006-01-02")
	if today != cl.date {
		if err := cl.rotate(today); err != nil {
			return
		}
	}
	if cl.file != nil {
		data, _ := json.Marshal(rec)
		cl.file.Write(append(data, '\n'))
	}
}

func (cl *ConnLogger) rotate(today string) error {
	if cl.file != nil {
		cl.file.Close()
	}
	path := filepath.Join(cl.dir, fmt.Sprintf("connections-%s.jsonl", today))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	cl.file = f
	cl.date = today
	return nil
}

func (cl *ConnLogger) Close() {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	if cl.file != nil {
		cl.file.Close()
		cl.file = nil
	}
}
