package ss

import (
	"os"
	"testing"
)

func TestConfig_RuntimeInit(t *testing.T) {
	c := &Config{}
	if c.rt != nil {
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
	CheckLogFile(c)
	CheckBasicConfig(c)

	l := c.getLogger()
	if l == nil {
		t.Error("getLogger should return logger after CheckBasicConfig")
	}
}

func TestConfig_LogMethods(t *testing.T) {
	c := &Config{Nickname: "testlog"}
	CheckLogFile(c)
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

func TestConfig_SetGetPool(t *testing.T) {
	c := &Config{}

	if p := c.getPool(); p != nil {
		t.Error("pool should be nil initially")
	}

	pool := NewConnPool()
	c.setPool(pool)
	if c.getPool() != pool {
		t.Error("getPool should return set pool")
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

	CheckLogFile(c)
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
	CheckLogFile(c)
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

func TestConfig_LogFileStderr(t *testing.T) {
	c := &Config{}
	CheckLogFile(c)
	if lf := c.getLogFile(); lf != os.Stderr {
		t.Errorf("expected logfile to be stderr, got %v", lf)
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
