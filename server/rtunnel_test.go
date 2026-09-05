package server

import (
	"testing"
	"time"
)

func TestBumpBackoff(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want time.Duration
	}{
		{rtunnelBackoffBase, 4 * time.Second},
		{8 * time.Second, 16 * time.Second},
		{16 * time.Second, rtunnelMaxBackoff}, // 32s clamps to 30s
		{rtunnelMaxBackoff, rtunnelMaxBackoff},
	}
	for _, c := range cases {
		if got := bumpBackoff(c.in); got != c.want {
			t.Errorf("bumpBackoff(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestNextReconnectBackoff pins the reset rule: a session that stayed up for
// rtunnelSessionResetAfter resets the pace to base, anything shorter keeps
// escalating — a server that accepts dials but immediately rejects sessions
// must not stay pinned at the base interval.
func TestNextReconnectBackoff(t *testing.T) {
	if got := nextReconnectBackoff(0, rtunnelBackoffBase); got != 4*time.Second {
		t.Errorf("instant teardown should escalate: got %v, want 4s", got)
	}
	if got := nextReconnectBackoff(rtunnelSessionResetAfter-time.Second, 16*time.Second); got != rtunnelMaxBackoff {
		t.Errorf("short session should escalate: got %v, want %v", got, rtunnelMaxBackoff)
	}
	if got := nextReconnectBackoff(rtunnelSessionResetAfter, 16*time.Second); got != rtunnelBackoffBase {
		t.Errorf("healthy session should reset: got %v, want %v", got, rtunnelBackoffBase)
	}
	if got := nextReconnectBackoff(time.Hour, rtunnelMaxBackoff); got != rtunnelBackoffBase {
		t.Errorf("long-lived session should reset: got %v, want %v", got, rtunnelBackoffBase)
	}
}
