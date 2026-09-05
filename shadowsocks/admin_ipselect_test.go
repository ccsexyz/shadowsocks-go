package ss

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminIPSelectPropagation(t *testing.T) {
	parent := &Config{}
	backend := &Config{Nickname: "backend-a"}
	parent.Backends = []*Config{backend}

	oldCfgs := getAdminConfigs()
	SetAdminConfigs([]*Config{parent})
	t.Cleanup(func() { SetAdminConfigs(oldCfgs) })

	t.Run("settings propagate to backends", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/configs/0/settings",
			strings.NewReader(`{"ipselect":"off","ipselect_delay_ms":0}`))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("index", "0")
		rr := httptest.NewRecorder()
		handleUpdateSettings(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("settings status = %d, body = %s", rr.Code, rr.Body.String())
		}
		if parent.IPSelect != ipSelectOff {
			t.Errorf("parent ipselect = %q, want off", parent.IPSelect)
		}
		if backend.IPSelect != ipSelectOff {
			t.Errorf("backend ipselect = %q, want off", backend.IPSelect)
		}
		if parent.IPSelectDelayMs != defaultIPSelectDelayMs || backend.IPSelectDelayMs != defaultIPSelectDelayMs {
			t.Errorf("delay should normalize to default: parent=%d backend=%d", parent.IPSelectDelayMs, backend.IPSelectDelayMs)
		}
	})

	t.Run("backend update supports ipselect", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/configs/0/backends/backend-a",
			strings.NewReader(`{"ipselect":"race","ipselect_delay_ms":25}`))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("index", "0")
		req.SetPathValue("nickname", "backend-a")
		rr := httptest.NewRecorder()
		handleUpdateBackend(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("backend status = %d, body = %s", rr.Code, rr.Body.String())
		}
		if backend.IPSelect != ipSelectRace {
			t.Errorf("backend ipselect = %q, want race", backend.IPSelect)
		}
		if backend.IPSelectDelayMs != 25 {
			t.Errorf("backend delay = %d, want 25", backend.IPSelectDelayMs)
		}
	})

	t.Run("backend delay zero inherits parent", func(t *testing.T) {
		parent.IPSelectDelayMs = 321
		req := httptest.NewRequest(http.MethodPut, "/api/configs/0/backends/backend-a",
			strings.NewReader(`{"ipselect_delay_ms":0}`))
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("index", "0")
		req.SetPathValue("nickname", "backend-a")
		rr := httptest.NewRecorder()
		handleUpdateBackend(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("backend status = %d, body = %s", rr.Code, rr.Body.String())
		}
		if backend.IPSelectDelayMs != parent.IPSelectDelayMs {
			t.Errorf("backend delay = %d, want parent delay %d", backend.IPSelectDelayMs, parent.IPSelectDelayMs)
		}
	})
}

// TestAdminDialPolicySnapshotRefresh pins the copy-on-write contract of the
// per-dial policy snapshot: the settings endpoint republishes the atomic
// snapshot for the parent and its backends, so the next dialPolicy() call
// observes the new values as one consistent view.
func TestAdminDialPolicySnapshotRefresh(t *testing.T) {
	parent := &Config{NetworkConfig: NetworkConfig{IPSelectDelayMs: 123}}
	backend := &Config{Nickname: "backend-b"}
	parent.Backends = []*Config{backend}
	CheckBasicConfig(parent)

	oldSnapshot := parent.dialPolicy()
	if oldSnapshot.ipSelectDelay != 123 {
		t.Fatalf("initial snapshot delay = %d, want 123", oldSnapshot.ipSelectDelay)
	}

	oldCfgs := getAdminConfigs()
	SetAdminConfigs([]*Config{parent})
	t.Cleanup(func() { SetAdminConfigs(oldCfgs) })

	req := httptest.NewRequest(http.MethodPut, "/api/configs/0/settings",
		strings.NewReader(`{"ipselect":"race","ipselect_delay_ms":77,"prefer_ipv4":true}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	handleUpdateSettings(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("settings status = %d, body = %s", rr.Code, rr.Body.String())
	}

	fresh := parent.dialPolicy()
	if fresh == oldSnapshot {
		t.Fatal("snapshot was not republished")
	}
	if fresh.ipSelect != ipSelectRace || fresh.ipSelectDelay != 77 || !fresh.preferIPv4 {
		t.Errorf("parent snapshot = %+v", fresh)
	}
	// All dial-policy fields propagate to backends in the settings endpoint
	// (ipselect, ipselect_delay_ms, prefer_ipv4 — matching the startup
	// inheritance in CheckConfig), and the backend snapshot is republished.
	if bp := backend.dialPolicy(); bp.ipSelectDelay != 77 || bp.ipSelect != ipSelectRace || !bp.preferIPv4 {
		t.Errorf("backend snapshot = %+v", bp)
	}
}
