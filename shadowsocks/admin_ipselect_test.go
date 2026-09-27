package ss

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

func TestAdminIPSelectEndpoint(t *testing.T) {
	parent := &Config{NetworkConfig: NetworkConfig{IPSelect: ipSelectSmart, IPSelectDelayMs: 40}}
	backend := &Config{Nickname: "hk", NetworkConfig: NetworkConfig{IPSelect: ipSelectSmart}}
	parent.Backends = []*Config{backend}
	CheckBasicConfig(parent)
	CheckBasicConfig(backend)

	oldCfgs := getAdminConfigs()
	SetAdminConfigs([]*Config{parent})
	t.Cleanup(func() { SetAdminConfigs(oldCfgs) })

	// Seed stats and one decision on each cache: the parent dialed a.test
	// successfully, the backend b.test never connected.
	parent.getIPSelectCache().record("a.test", "1.2.3.4", 10*time.Millisecond, true)
	parent.getIPSelectCache().recordDecision(ipSelDecision{
		Time: time.Now().Add(-time.Second), Host: "a.test",
		Reason: ipSelReasonSingle, Winner: "1.2.3.4",
	})
	backend.getIPSelectCache().record("b.test", "5.6.7.8", 20*time.Millisecond, false)
	backend.getIPSelectCache().recordDecision(ipSelDecision{
		Time: time.Now(), Host: "b.test", Reason: ipSelReasonFailed, Error: "boom",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/configs/0/ipselect", nil)
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	handleIPSelect(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	var st ipSelectStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode != ipSelectSmart || st.DelayMs != 40 {
		t.Errorf("mode/delay = %s/%d, want smart/40", st.Mode, st.DelayMs)
	}
	if len(st.Hosts) != 2 {
		t.Fatalf("hosts = %+v", st.Hosts)
	}
	self, bk := st.Hosts[0], st.Hosts[1]
	if self.Host != "a.test" || self.Source != "" {
		t.Errorf("self host entry = %+v", self)
	}
	if len(self.Candidates) != 1 || self.Candidates[0].IP != "1.2.3.4" ||
		self.Candidates[0].Success != 1 || self.Candidates[0].ScoreMs <= 0 {
		t.Errorf("self candidates = %+v", self.Candidates)
	}
	if bk.Host != "b.test" || bk.Source != "hk" {
		t.Errorf("backend host entry = %+v", bk)
	}
	if len(bk.Candidates) != 1 || bk.Candidates[0].ScoreMs != ipSelScoreNeverConnected {
		t.Errorf("never-connected candidate should carry the sentinel: %+v", bk.Candidates)
	}
	if len(st.History) != 2 {
		t.Fatalf("history = %+v", st.History)
	}
	// Newest first, each tagged with its source.
	if st.History[0].Host != "b.test" || st.History[0].Source != "hk" || st.History[0].Error != "boom" {
		t.Errorf("history[0] = %+v", st.History[0])
	}
	if st.History[1].Host != "a.test" || st.History[1].Source != "" || st.History[1].Winner != "1.2.3.4" {
		t.Errorf("history[1] = %+v", st.History[1])
	}
}

func TestAdminIPSelectEndpointOff(t *testing.T) {
	parent := &Config{}
	CheckBasicConfig(parent)
	oldCfgs := getAdminConfigs()
	SetAdminConfigs([]*Config{parent})
	t.Cleanup(func() { SetAdminConfigs(oldCfgs) })

	req := httptest.NewRequest(http.MethodGet, "/api/configs/0/ipselect", nil)
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	handleIPSelect(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var st ipSelectStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode != ipSelectOff || len(st.Hosts) != 0 || len(st.History) != 0 {
		t.Errorf("off-mode status = %+v", st)
	}
}

func TestAdminIPSelectEndpointRaceKeepsHistoryOnly(t *testing.T) {
	parent := &Config{NetworkConfig: NetworkConfig{IPSelect: ipSelectRace}}
	CheckBasicConfig(parent)
	oldCfgs := getAdminConfigs()
	SetAdminConfigs([]*Config{parent})
	t.Cleanup(func() { SetAdminConfigs(oldCfgs) })

	// Leftover stats from an earlier smart-mode run must not surface in race
	// mode — they no longer describe the dial order — but decisions still do.
	parent.getIPSelectCache().record("stale.test", "1.2.3.4", 10*time.Millisecond, true)
	parent.getIPSelectCache().recordDecision(ipSelDecision{
		Time: time.Now(), Host: "stale.test", Reason: ipSelReasonRace, Winner: "1.2.3.4",
	})

	req := httptest.NewRequest(http.MethodGet, "/api/configs/0/ipselect", nil)
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	handleIPSelect(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	var st ipSelectStatus
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Mode != ipSelectRace {
		t.Errorf("mode = %s, want race", st.Mode)
	}
	if len(st.Hosts) != 0 {
		t.Errorf("race mode should not report host stats, got %+v", st.Hosts)
	}
	if len(st.History) != 1 || st.History[0].Host != "stale.test" {
		t.Errorf("race mode should still report history, got %+v", st.History)
	}
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
