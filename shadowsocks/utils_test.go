package ss

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

// fakePipeConn is a minimal Conn for driving Pipe in tests.
type fakePipeConn struct {
	steps    []fakeStep
	release  chan struct{} // when set, Read blocks until released
	received []byte
	writes   []int
}

// fakeStep is one Read result: either data or an error.
type fakeStep struct {
	data []byte
	err  error
}

func (c *fakePipeConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	if c.release != nil {
		<-c.release
		return nil, io.EOF
	}
	if len(c.steps) == 0 {
		return nil, io.EOF
	}
	s := c.steps[0]
	c.steps = c.steps[1:]
	if s.err != nil {
		return nil, s.err
	}
	n := copy(buf, s.data)
	return [][]byte{buf[:n]}, nil
}

func (c *fakePipeConn) Write(bufs ...[]byte) (int, error) {
	n := 0
	for _, b := range bufs {
		n += len(b)
		c.received = append(c.received, b...)
	}
	c.writes = append(c.writes, n)
	return n, nil
}

func (c *fakePipeConn) Close() error                       { return nil }
func (c *fakePipeConn) LocalAddr() net.Addr                { return nil }
func (c *fakePipeConn) RemoteAddr() net.Addr               { return nil }
func (c *fakePipeConn) SetDeadline(_ time.Time) error      { return nil }
func (c *fakePipeConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *fakePipeConn) SetWriteDeadline(_ time.Time) error { return nil }

// TestPipe_SkipsEmptyWrites verifies that a (0, nil) read is not forwarded as
// a zero-length write downstream.
func TestPipe_SkipsEmptyWrites(t *testing.T) {
	src := &fakePipeConn{
		steps: []fakeStep{
			{}, // (0, nil): no data, no error
			{data: []byte("hello")},
			{err: io.EOF},
		},
	}
	dst := &fakePipeConn{release: make(chan struct{})}

	Pipe(src, dst, &Config{})
	close(dst.release)

	if len(dst.writes) == 0 {
		t.Fatal("no writes reached the destination")
	}
	for i, n := range dst.writes {
		if n == 0 {
			t.Fatalf("write %d forwarded zero bytes", i)
		}
	}
	if string(dst.received) != "hello" {
		t.Fatalf("payload mismatch: %q", dst.received)
	}
}

// TestLimiterNegativeLimitDoesNotBlock pins that a negative (misconfigured)
// limit degrades to unlimited: Update must return instead of draining tokens
// forever while holding the lock.
func TestLimiterNegativeLimitDoesNotBlock(t *testing.T) {
	l := NewLimiter(-1)
	done := make(chan struct{})
	go func() {
		l.Update(100)
		l.Update(100)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Update with negative limit deadlocked")
	}
}

// TestShardedFilterReplayDetection pins the UDP/TCP replay-filter semantics:
// a seen value is reported as a replay, Reset forgets it, and concurrent use
// is safe (run with -race).
func TestShardedFilterReplayDetection(t *testing.T) {
	f := newShardedFilter(1024, 0.001)
	defer f.Close()
	v := []byte("replay-marker")
	if f.TestAndAdd(v) {
		t.Fatal("first TestAndAdd must be false")
	}
	if !f.TestAndAdd(v) {
		t.Fatal("second TestAndAdd must be true (replay detected)")
	}
	f.Reset()
	if f.TestAndAdd(v) {
		t.Fatal("after Reset the marker must be forgotten")
	}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				f.TestAndAdd([]byte{byte(g), byte(i)})
			}
		}(g)
	}
	wg.Wait()
}
