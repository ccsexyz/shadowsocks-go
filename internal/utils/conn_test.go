package utils

import (
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// newUDPTestConn returns a loopback UDP PacketConn for SubConn tests.
func newUDPTestConn(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	return pc
}

// TestSubConnCloseKeepsReplacementSession pins the conditional map delete:
// when an old session closes after a replacement was stored under the same
// remote address, the replacement must survive.
func TestSubConnCloseKeepsReplacementSession(t *testing.T) {
	pc1 := newUDPTestConn(t)
	defer pc1.Close()
	ctx := &UDPServerCtx{}
	ctx.init()

	key := "127.0.0.1:5555"
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5555}

	old := newSubConn(pc1, ctx, addr)
	ctx.connsMap.Store(key, old)

	// A new session for the same remote address replaces the old one...
	pc2 := newUDPTestConn(t)
	defer pc2.Close()
	fresh := newSubConn(pc2, ctx, addr)
	ctx.connsMap.Store(key, fresh)

	// ...then the old session closes: it must not evict the fresh one.
	old.Close()

	if v, ok := ctx.connsMap.Load(key); !ok || v != any(fresh) {
		t.Fatalf("fresh SubConn was evicted by old session close (ok=%v)", ok)
	}

	// Closing the fresh one removes it.
	fresh.Close()
	if _, ok := ctx.connsMap.Load(key); ok {
		t.Fatal("fresh SubConn still present after its own close")
	}
}

// TestSubConnCloseStopsTimer ensures Close stops the idle timer so churned
// UDP sessions don't leave dead timers on the runtime heap for up to an hour.
// The timer is created with a one-hour duration, so Stop() returning true
// after Close means Close failed to stop it — it cannot have expired on its
// own within the test.
func TestSubConnCloseStopsTimer(t *testing.T) {
	pc := newUDPTestConn(t)
	defer pc.Close()
	ctx := &UDPServerCtx{}
	ctx.init()
	sc := newSubConn(pc, ctx, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})
	sc.Close()
	if sc.rtimer.Stop() {
		t.Error("idle timer still running after Close")
	}
}

// errPacketConn fails every ReadFrom with a non-ErrClosed error, standing in
// for a socket stuck in a persistent per-read error state.
type errPacketConn struct {
	calls atomic.Int64
}

func (c *errPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	c.calls.Add(1)
	return 0, nil, errors.New("persistent socket error")
}
func (c *errPacketConn) Close() error { return nil }
func (c *errPacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *errPacketConn) WriteTo(_ []byte, _ net.Addr) (int, error) { return 0, nil }
func (c *errPacketConn) SetDeadline(_ time.Time) error             { return nil }
func (c *errPacketConn) SetReadDeadline(_ time.Time) error         { return nil }
func (c *errPacketConn) SetWriteDeadline(_ time.Time) error        { return nil }

// TestRunUDPServerBacksOffOnPersistentReadErrors pins the error-loop
// behavior: non-ErrClosed ReadFrom errors keep the loop alive but back off,
// instead of spinning hot or killing the relay.
func TestRunUDPServerBacksOffOnPersistentReadErrors(t *testing.T) {
	ctx := &UDPServerCtx{}
	ctx.init()
	defer ctx.close()

	stub := &errPacketConn{}
	done := make(chan struct{})
	go func() {
		ctx.runUDPServer(stub, func(*SubConn) {})
		close(done)
	}()

	time.Sleep(150 * time.Millisecond)
	close(ctx.die)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runUDPServer did not exit after ctx.die")
	}

	// Without the backoff a hot loop would log thousands of iterations in
	// 150ms; with the escalating 10ms steps only a handful fit. Keep the
	// bounds generous to stay robust on slow CI machines.
	calls := stub.calls.Load()
	if calls == 0 {
		t.Fatal("ReadFrom was never called")
	}
	if calls > 30 {
		t.Fatalf("error loop is spinning hot: %d read attempts in 150ms", calls)
	}
}
