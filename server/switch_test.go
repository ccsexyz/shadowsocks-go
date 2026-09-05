package server

import (
	"testing"

	ss "github.com/ccsexyz/shadowsocks-go/shadowsocks"
)

// TestFindActiveBackendStartupAssignment pins the startup sequence: an admin
// read may resolve the active-backend snapshot (empty) before runServer's
// default assignment; the assignment goes through SetActiveBackend, so the
// switch handler must still resolve the first backend afterwards.
func TestFindActiveBackendStartupAssignment(t *testing.T) {
	c := &ss.Config{}
	c.Nickname = "switch"
	b := &ss.Config{Nickname: "b-offer"}
	c.Backends = []*ss.Config{b}
	ss.CheckBasicConfig(c)

	// Admin GET /api/configs arrives first and publishes the empty snapshot.
	if got := c.GetActiveBackend(); got != "" {
		t.Fatalf("initial active = %q, want empty", got)
	}

	// main.go "switch" path.
	if backends := c.SnapshotBackends(); c.GetActiveBackend() == "" && len(backends) > 0 {
		c.SetActiveBackend(backends[0].Nickname)
	}

	if got := findActiveBackend(c); got == nil || got.Nickname != "b-offer" {
		t.Fatalf("findActiveBackend after startup assignment = %+v, want b-offer", got)
	}
}
