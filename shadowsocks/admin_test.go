package ss

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestAdminHostAllowed(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"127.0.0.1:9090", true},
		{"127.0.0.1", true},
		{"[::1]:9090", true},
		{"::1", true},
		{"192.168.1.10:9090", true},
		{"localhost:9090", true},
		{"LOCALHOST", true},
		// DNS names are exactly what a rebinding attack needs; reject them.
		{"attacker.example:9090", false},
		{"attacker.example", false},
		{"", false},
	}
	for _, c := range cases {
		if got := adminHostAllowed(c.host); got != c.want {
			t.Errorf("adminHostAllowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// TestAdminAddBackendRequiresJSONContentType pins the CSRF guard: a browser
// no-cors POST (text/plain body carrying JSON) must be rejected even though
// it decodes as valid JSON.
func TestAdminAddBackendRequiresJSONContentType(t *testing.T) {
	parent := &Config{Nickname: "parent"}
	parent.Backends = []*Config{}
	SetAdminConfigs([]*Config{parent})
	t.Cleanup(func() { SetAdminConfigs(nil) })

	req := httptest.NewRequest(http.MethodPost, "/api/configs/0/backends",
		strings.NewReader(`{"nickname":"evil","remoteaddr":"1.2.3.4:80"}`))
	// No Content-Type set: fetch() defaults to text/plain for string bodies.
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	handleAddBackend(rr, req)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain POST status = %d, want 415", rr.Code)
	}
	if len(parent.Backends) != 0 {
		t.Fatalf("backend was added despite rejected request")
	}

	req = httptest.NewRequest(http.MethodPost, "/api/configs/0/backends",
		strings.NewReader(`{"nickname":"ok","remoteaddr":"1.2.3.4:80"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("index", "0")
	rr = httptest.NewRecorder()
	handleAddBackend(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("application/json POST status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if len(parent.Backends) != 1 {
		t.Fatalf("backend not added with correct content type")
	}
}

// TestToIntRejectsOutOfRange pins the bounds on toInt: float64 values beyond
// int range have implementation-defined conversion behavior, and huge numeric
// strings must error instead of silently wrapping.
func TestToIntRejectsOutOfRange(t *testing.T) {
	if _, err := toInt(1e308); err == nil {
		t.Error("1e308 should be rejected (implementation-defined conversion)")
	}
	if _, err := toInt(-1e308); err == nil {
		t.Error("-1e308 should be rejected")
	}
	if _, err := toInt("99999999999999999999999"); err == nil {
		t.Error("huge numeric string should be rejected")
	}
	if v, err := toInt(float64(150)); err != nil || v != 150 {
		t.Errorf("toInt(150) = %v, %v", v, err)
	}
	if _, err := toInt("not-a-number"); err == nil {
		t.Error("junk string should fail")
	}
}

// TestAdminAddrIsLoopbackOnly pins the listen-address guard for the built-in
// admin service: only loopback forms are allowed, wildcard and LAN addresses
// (and unparseable ones) are rejected.
func TestAdminAddrIsLoopbackOnly(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080":  true,
		"localhost:8080":  true,
		"LOCALHOST:80":    true,
		"[::1]:8080":      true,
		"0.0.0.0:8080":    false,
		":8080":           false,
		"[::]:8080":       false,
		"192.168.1.5:808": false,
		"noport":          false,
	}
	for addr, want := range cases {
		if got := adminAddrIsLoopbackOnly(addr); got != want {
			t.Errorf("adminAddrIsLoopbackOnly(%q) = %v, want %v", addr, got, want)
		}
	}
}

// TestAdminSetActiveBackendPublishesSnapshot pins the lock-free snapshot
// republish: GetActiveBackend serves a cached atomic snapshot on the
// switch-mode hot path, so a settings-style write that skips republishing
// would leave every reader on a stale value forever.
func TestAdminSetActiveBackendPublishesSnapshot(t *testing.T) {
	parent := &Config{Nickname: "parent"}
	parent.Backends = []*Config{{Nickname: "backend-a"}, {Nickname: "backend-b"}}
	CheckBasicConfig(parent)
	SetAdminConfigs([]*Config{parent})
	t.Cleanup(func() { SetAdminConfigs(nil) })

	// Prime the cached snapshot with the pre-change value.
	if got := parent.GetActiveBackend(); got != "" {
		t.Fatalf("initial active = %q, want empty", got)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/configs/0/active",
		strings.NewReader(`{"nickname":"backend-b"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("index", "0")
	rr := httptest.NewRecorder()
	handleSetActiveBackend(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}

	if got := parent.GetActiveBackend(); got != "backend-b" {
		t.Fatalf("GetActiveBackend after set = %q, want backend-b (stale snapshot?)", got)
	}
}

// TestAdminDeleteBackendResetsActiveBackend pins that deleting the
// switch-mode target re-points ActiveBackend at the first remaining backend
// (or clears it when none remain) — otherwise the switch handler fails every
// subsequent connection on a dangling nickname.
func TestAdminDeleteBackendResetsActiveBackend(t *testing.T) {
	parent := &Config{Nickname: "parent", ActiveBackend: "backend-a"}
	parent.Backends = []*Config{{Nickname: "backend-a"}, {Nickname: "backend-b"}}
	CheckBasicConfig(parent)
	SetAdminConfigs([]*Config{parent})
	t.Cleanup(func() { SetAdminConfigs(nil) })

	del := func(nickname string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/configs/0/backends/"+nickname, nil)
		req.SetPathValue("index", "0")
		req.SetPathValue("nickname", nickname)
		rr := httptest.NewRecorder()
		handleDeleteBackend(rr, req)
		return rr
	}

	if rr := del("backend-a"); rr.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if got := parent.GetActiveBackend(); got != "backend-b" {
		t.Fatalf("active after deleting the active backend = %q, want backend-b", got)
	}

	if rr := del("backend-b"); rr.Code != http.StatusOK {
		t.Fatalf("delete status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if got := parent.GetActiveBackend(); got != "" {
		t.Fatalf("active after deleting the last backend = %q, want empty", got)
	}
}

// TestSetActiveBackendRepublishesSnapshot pins the startup path: runServer's
// "switch" default assignment must republish the cached snapshot, otherwise
// an admin read that resolved the empty value first freezes it forever.
func TestSetActiveBackendRepublishesSnapshot(t *testing.T) {
	c := &Config{}
	if got := c.GetActiveBackend(); got != "" {
		t.Fatalf("initial active = %q, want empty", got)
	}
	c.SetActiveBackend("backend-a")
	if got := c.GetActiveBackend(); got != "backend-a" {
		t.Fatalf("active after SetActiveBackend = %q, want backend-a (stale snapshot?)", got)
	}
}

// TestAdminLiveConfigReadWriteRaces is a concurrency regression for the
// admin read paths: run with -race. The settings writer and the raw/summary
// readers must be serialized by adminWriteMu, and the accept-path
// RegisterLocalAddr must not race the raw reader either.
func TestAdminLiveConfigReadWriteRaces(t *testing.T) {
	c := &Config{}
	c.Nickname = "verify"
	c.Localaddr = "127.0.0.1:1"
	CheckBasicConfig(c)

	old := getAdminConfigs()
	SetAdminConfigs([]*Config{c})
	t.Cleanup(func() { SetAdminConfigs(old) })

	const iterations = 300
	var wg sync.WaitGroup
	wg.Add(4)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			c.RegisterLocalAddr("127.0.0.1:2")
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodPut, "/api/configs/0/settings",
				strings.NewReader(`{"ipselect":"race","ipselect_delay_ms":77}`))
			req.Header.Set("Content-Type", "application/json")
			req.SetPathValue("index", "0")
			handleUpdateSettings(httptest.NewRecorder(), req)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/configs/0/config", nil)
			req.SetPathValue("index", "0")
			rr := httptest.NewRecorder()
			handleGetConfigRaw(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("raw status = %d", rr.Code)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			req := httptest.NewRequest(http.MethodGet, "/api/configs", nil)
			rr := httptest.NewRecorder()
			handleListConfigs(rr, req)
			if rr.Code != http.StatusOK {
				t.Errorf("list status = %d", rr.Code)
				return
			}
		}
	}()
	wg.Wait()
}
