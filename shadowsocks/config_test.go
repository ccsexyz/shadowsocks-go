package ss

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_RuntimeInit(t *testing.T) {
	c := &Config{}
	if c.rt.Load() != nil {
		t.Error("runtime should be nil before init")
	}

	rt := c.InitRuntime()
	if rt == nil {
		t.Fatal("InitRuntime returned nil")
	}
	if rt.Die == nil {
		t.Error("Die channel should be created")
	}

	// Second call returns same runtime
	rt2 := c.InitRuntime()
	if rt != rt2 {
		t.Error("InitRuntime should return same runtime")
	}
}

func TestConfig_AccessorsOnNil(t *testing.T) {
	c := &Config{} // no runtime

	if s := c.getStat(); s == nil {
		// getStat should create runtime and stat
		// Let's verify it does create it
	}
	if l := c.getLogger(); l != nil {
		t.Error("getLogger should return nil on nil runtime")
	}
	if v := c.getVLogger(); v != nil {
		t.Error("getVLogger should return nil on nil runtime")
	}
	if d := c.getDLogger(); d != nil {
		t.Error("getDLogger should return nil on nil runtime")
	}
	if l := c.getLimiters(); l != nil {
		t.Error("getLimiters should return nil on nil runtime")
	}
}

func TestConfig_AccessorsAfterInit(t *testing.T) {
	c := &Config{}
	c.InitRuntime()

	if s := c.getStat(); s == nil {
		t.Error("getStat should create stat server")
	}
	if d := c.DieChan(); d == nil {
		t.Error("DieChan should return channel")
	}
}

func TestConfig_LoggerAccessors(t *testing.T) {
	c := &Config{Nickname: "test"}
	CheckBasicConfig(c)

	l := c.getLogger()
	if l == nil {
		t.Error("getLogger should return logger after CheckBasicConfig")
	}
}

func TestConfig_LogMethods(t *testing.T) {
	c := &Config{Nickname: "testlog"}
	CheckBasicConfig(c)

	// Should not panic
	c.Log("test log message")
	c.LogV("test verbose message")
	c.LogD("test debug message")
}

func TestConfig_Disabled(t *testing.T) {
	c := &Config{}

	if c.isDisabled() {
		t.Error("should not be disabled by default")
	}

	c.setDisabled(true)
	if !c.isDisabled() {
		t.Error("should be disabled after setting")
	}

	c.setDisabled(false)
	if c.isDisabled() {
		t.Error("should not be disabled after clearing")
	}
}

func TestConfig_StatAccess(t *testing.T) {
	c := &Config{}

	s := c.getStat()
	if s == nil {
		t.Fatal("getStat should create stat")
	}

	s2 := c.getStat()
	if s != s2 {
		t.Error("getStat should return same stat")
	}
}

func TestConfig_Close(t *testing.T) {
	c := &Config{Nickname: "testclose"}
	c.InitRuntime()
	c.Close() // should not panic

	// Close again should be safe
	c.Close()
}

func TestConfig_BackendInheritance(t *testing.T) {
	c := &Config{
		Nickname: "parent",
		NetworkConfig: NetworkConfig{
			Type:       "server",
			Remoteaddr: "example.com:443",
			Timeout:    60,
		},
		ObfsConfig: ObfsConfig{Obfs: true},
		CryptoConfig: CryptoConfig{
			Method:   "aes-256-gcm",
			Password: "testpass",
		},
	}
	c.Backends = append(c.Backends, &Config{
		Nickname: "child",
		CryptoConfig: CryptoConfig{
			Method: "aes-256-gcm",
		},
	})

	c.InitRuntime()
	CheckConfig(c)

	if len(c.Backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(c.Backends))
	}
	child := c.Backends[0]
	if child.getStat() == nil {
		t.Error("child should have stat initialized")
	}
}

func TestConfig_CheckBasicDefaults(t *testing.T) {
	c := &Config{}
	CheckBasicConfig(c)

	if c.Method != defaultMethod {
		t.Errorf("expected method %q, got %q", defaultMethod, c.Method)
	}
	if c.Password != defaultPassword {
		t.Errorf("expected password %q, got %q", defaultPassword, c.Password)
	}
	if c.Ivlen == 0 {
		t.Error("expected non-zero ivlen")
	}
	if c.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}
	if c.FilterCapacity == 0 {
		t.Error("expected non-zero filter capacity")
	}
}

func TestConfig_DieChannel(t *testing.T) {
	c := &Config{}
	die := c.DieChan()
	if die == nil {
		t.Fatal("DieChan returned nil")
	}

	// Should be open initially
	select {
	case <-die:
		t.Error("Die channel should be open initially")
	default:
	}

	c.Close()

	// After Close, Die should be closed
	_, ok := <-die
	if ok {
		t.Error("Die channel should be closed after Close")
	}
}

// TestReadConfigRejectsEmptyOrNullConfigs pins the nil-entry filter in
// ReadConfig: "[null]" unmarshals into a slice with a nil entry that used to
// panic in CheckConfig, and an empty file used to yield zero servers and
// start silently.
func TestReadConfigRejectsEmptyOrNullConfigs(t *testing.T) {
	dir := t.TempDir()
	for _, content := range []string{"[null]", "null", "[]", ""} {
		p := filepath.Join(dir, "cfg.json")
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadConfig(p); err == nil {
			t.Errorf("ReadConfig(%q) should return an error, got nil", content)
		}
	}
}

// TestCheckBasicConfigOwnLimiterPreservesParent pins the limiter-ownership
// rule: a backend created with Limit==0 inherits the parent limiters; a
// later admin edit that sets Limit must prepend the config's own limiter
// instead of overwriting slot 0 (which held the inherited parent limiter),
// and repeated CheckBasicConfig calls must keep replacing only the own slot.
func TestCheckBasicConfigOwnLimiterPreservesParent(t *testing.T) {
	c := &Config{}
	CheckBasicConfig(c)
	if len(c.getLimiters()) != 0 {
		t.Fatalf("Limit==0 must not create a limiter, got %d", len(c.getLimiters()))
	}

	// Simulate handleAddBackend inheriting the parent's limiters.
	parentLimiter := NewLimiter(5000)
	c.initRuntime().limiters = append(c.initRuntime().limiters, parentLimiter)

	c.Limit = 100
	CheckBasicConfig(c)
	ls := c.getLimiters()
	if len(ls) != 2 {
		t.Fatalf("limiter count = %d, want own + inherited", len(ls))
	}
	if ls[1] != parentLimiter {
		t.Fatal("inherited parent limiter was clobbered by the own limiter")
	}
	if ls[0].GetLimit() != 100 {
		t.Fatalf("own limiter limit = %d, want 100", ls[0].GetLimit())
	}

	// Re-running CheckBasicConfig (admin edits method/password) replaces the
	// own limiter only.
	c.Limit = 200
	CheckBasicConfig(c)
	ls = c.getLimiters()
	if len(ls) != 2 {
		t.Fatalf("limiter count = %d after re-check, want 2 (no stacking)", len(ls))
	}
	if ls[1] != parentLimiter {
		t.Fatal("parent limiter lost on re-check")
	}
	if ls[0].GetLimit() != 200 {
		t.Fatalf("own limiter limit = %d, want 200", ls[0].GetLimit())
	}
}
