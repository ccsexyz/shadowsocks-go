package ss

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
)

// --- mock connection for testing ---

type mockConn struct {
	readBuf    []byte
	readPos    int
	writeBuf   []byte
	closed     bool
	readDelay  time.Duration
	localAddr  net.Addr
	remoteAddr net.Addr
	mu         sync.Mutex
}

func newMockConn() *mockConn {
	return &mockConn{
		localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20000},
	}
}

func (m *mockConn) Read(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, net.ErrClosed
	}
	if m.readPos >= len(m.readBuf) {
		return 0, io.EOF
	}
	n := copy(b, m.readBuf[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, net.ErrClosed
	}
	m.writeBuf = append(m.writeBuf, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return m.localAddr }
func (m *mockConn) RemoteAddr() net.Addr               { return m.remoteAddr }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *mockConn) getWritten() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]byte{}, m.writeBuf...)
}

func (m *mockConn) setReadData(data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readBuf = append([]byte{}, data...)
	m.readPos = 0
}

// mockConnWithBuffers implements WriteBuffers via the writev path
type mockConnWithBuffers struct {
	mockConn
	wbufs [][]byte
}

func newMockConnWithBuffers() *mockConnWithBuffers {
	return &mockConnWithBuffers{
		mockConn: mockConn{
			localAddr:  &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000},
			remoteAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20000},
		},
	}
}

func (m *mockConnWithBuffers) WriteBuffers(bufs [][]byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return 0, net.ErrClosed
	}
	total := 0
	for _, b := range bufs {
		m.writeBuf = append(m.writeBuf, b...)
		total += len(b)
		m.wbufs = append(m.wbufs, b)
	}
	return total, nil
}

// --- BaseConn tests ---

func TestBaseConn_WriteBuffers(t *testing.T) {
	mc := newMockConn()
	bc := newBaseConn(mc, nil)

	bufs := [][]byte{[]byte("hello "), []byte("world")}
	n, err := bc.WriteBuffers(bufs)
	if err != nil {
		t.Fatalf("WriteBuffers failed: %v", err)
	}
	if n != 11 {
		t.Errorf("expected 11 bytes written, got %d", n)
	}

	written := mc.getWritten()
	if string(written) != "hello world" {
		t.Errorf("expected 'hello world', got '%s'", string(written))
	}
}

func TestBaseConn_Metadata(t *testing.T) {
	cfg := &Config{CryptoConfig: CryptoConfig{Method: "aes-256-gcm"}}
	bc := newBaseConn(newMockConn(), cfg)

	if bc.GetCfg() != cfg {
		t.Error("GetCfg returned wrong config")
	}

	dst := &SockAddr{Hdr: []byte{3, 5, 'h', 'e', 'l', 'l', 'o', 0, 80}}
	bc.SetDst(dst)
	if bc.GetDst() != dst {
		t.Error("GetDst/SetDst roundtrip failed")
	}

	bc.SetHost("example.com")
	if bc.GetHost() != "example.com" {
		t.Errorf("GetHost/SetHost roundtrip failed, got %q", bc.GetHost())
	}
}

func TestBaseConn_WriteBuffersWithNetBuffers(t *testing.T) {
	// Test with a real TCP connection to exercise net.Buffers.WriteTo path
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	var serverErr error
	var serverData []byte

	go func() {
		defer wg.Done()
		conn, err := ln.Accept()
		if err != nil {
			serverErr = err
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			serverErr = err
			return
		}
		serverData = append([]byte{}, buf[:n]...)
	}()

	rawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()

	bc := newBaseConn(rawConn, nil)
	n, err := bc.WriteBuffers([][]byte{[]byte("part1-"), []byte("part2")})
	if err != nil {
		t.Fatalf("WriteBuffers failed: %v", err)
	}
	if n != 11 {
		t.Errorf("expected 11 bytes, got %d", n)
	}

	wg.Wait()
	if serverErr != nil {
		t.Fatal(serverErr)
	}
	if string(serverData) != "part1-part2" {
		t.Errorf("expected 'part1-part2', got '%s'", string(serverData))
	}
}

// --- RemainConn tests ---

func TestRemainConn_Read(t *testing.T) {
	mc := newMockConn()
	remain := []byte("cached-data")
	extra := []byte("-more-data")
	mc.setReadData(extra)

	rc := &RemainConn{Conn: newBaseConn(mc, nil), remain: remain}

	// First read should return from remain
	buf := make([]byte, 5)
	n, err := rc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(buf[:n]) != "cache" {
		t.Errorf("first read: got %d bytes '%s', want 5 bytes 'cache'", n, buf[:n])
	}

	// Second read should get remainder of remain
	n, err = rc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(buf[:n]) != "d-dat" {
		t.Errorf("second read: got %d bytes '%s', want 5 bytes 'd-dat'", n, buf[:n])
	}

	// Third read: last byte of remain
	n, err = rc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || string(buf[:n]) != "a" {
		t.Errorf("third read: got %d bytes '%s', want 1 byte 'a'", n, buf[:n])
	}

	// Fourth read: remain exhausted, reads from underlying conn
	n, err = rc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(buf[:n]) != "-more" {
		t.Errorf("fourth read: got %d bytes '%s', want 5 bytes '-more'", n, buf[:n])
	}
}

func TestRemainConn_ReadExactRemain(t *testing.T) {
	mc := newMockConn()
	remain := []byte("exact")
	mc.setReadData([]byte("ignored"))

	rc := &RemainConn{Conn: newBaseConn(mc, nil), remain: remain}

	buf := make([]byte, 5)
	n, err := rc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(buf[:n]) != "exact" {
		t.Errorf("got %d bytes '%s'", n, buf[:n])
	}

	// remain should be nil now
	if rc.remain != nil {
		t.Error("remain should be nil after exact read")
	}
}

func TestRemainConn_Write(t *testing.T) {
	mc := newMockConn()
	wremain := []byte("prefix-")
	rc := &RemainConn{Conn: newBaseConn(mc, nil), wremain: wremain}

	n, err := rc.Write([]byte("data"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("expected Write to return 4, got %d", n)
	}

	written := mc.getWritten()
	if string(written) != "prefix-data" {
		t.Errorf("expected 'prefix-data', got '%s'", string(written))
	}

	// wremain should be cleared
	if rc.wremain != nil {
		t.Error("wremain should be nil after write")
	}

	// Subsequent write should go directly through
	n, err = rc.Write([]byte("more"))
	if err != nil {
		t.Fatal(err)
	}
	written = mc.getWritten()
	if string(written) != "prefix-datamore" {
		t.Errorf("expected 'prefix-datamore', got '%s'", string(written))
	}
}

func TestRemainConn_WriteBuffers(t *testing.T) {
	mc := newMockConnWithBuffers()
	wremain := []byte("prefix-")
	rc := &RemainConn{Conn: newBaseConn(mc, nil), wremain: wremain}

	n, err := rc.WriteBuffers([][]byte{[]byte("hello"), []byte("-world")})
	if err != nil {
		t.Fatal(err)
	}
	if n != 11 {
		t.Errorf("expected 11 bytes total, got %d", n)
	}

	written := mc.getWritten()
	if string(written) != "prefix-hello-world" {
		t.Errorf("expected 'prefix-hello-world', got '%s'", string(written))
	}
}

func TestDecayRemainConn(t *testing.T) {
	mc := newMockConn()
	bc := newBaseConn(mc, nil)

	// Empty RemainConn should decay to inner
	rc := &RemainConn{Conn: bc}
	result := DecayRemainConn(rc)
	if _, ok := result.(*BaseConn); !ok {
		t.Errorf("empty RemainConn should decay to inner, got %T", result)
	}

	// RemainConn with remain should NOT decay
	rc2 := &RemainConn{Conn: bc, remain: []byte("data")}
	result2 := DecayRemainConn(rc2)
	if _, ok := result2.(*RemainConn); !ok {
		t.Errorf("RemainConn with remain should not decay, got %T", result2)
	}

	// RemainConn with wremain should NOT decay
	rc3 := &RemainConn{Conn: bc, wremain: []byte("data")}
	result3 := DecayRemainConn(rc3)
	if _, ok := result3.(*RemainConn); !ok {
		t.Errorf("RemainConn with wremain should not decay, got %T", result3)
	}
}

// --- LimitConn tests ---

func TestLimitConn_Read(t *testing.T) {
	mc := newMockConn()
	mc.setReadData([]byte("test-data"))

	limiter := &Limiter{limit: 1024 * 1024, last: time.Now().UnixNano(), nbytes: 1024 * 1024}
	lc := &LimitConn{
		Conn:      newBaseConn(mc, nil),
		Rlimiters: []*Limiter{limiter},
	}

	buf := make([]byte, 9)
	n, err := lc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 9 {
		t.Errorf("expected 9 bytes, got %d", n)
	}
	if string(buf[:n]) != "test-data" {
		t.Errorf("expected 'test-data', got '%s'", string(buf[:n]))
	}
}

func TestLimitConn_Write(t *testing.T) {
	mc := newMockConn()

	limiter := &Limiter{limit: 1024 * 1024, last: time.Now().UnixNano(), nbytes: 1024 * 1024}
	lc := &LimitConn{
		Conn:      newBaseConn(mc, nil),
		Wlimiters: []*Limiter{limiter},
	}

	n, err := lc.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes, got %d", n)
	}
}

// --- buildLimiters tests ---

func TestBuildLimiters_None(t *testing.T) {
	c := &Config{}
	limiters := buildLimiters(c)
	if len(limiters) != 0 {
		t.Errorf("expected 0 limiters, got %d", len(limiters))
	}
}

func TestBuildLimiters_GlobalOnly(t *testing.T) {
	c := &Config{
		LimitConfig: LimitConfig{Limit: 100},
	}
	c.InitRuntime().limiters = []*Limiter{NewLimiter(100)}
	limiters := buildLimiters(c)
	if len(limiters) != 1 {
		t.Errorf("expected 1 limiter, got %d", len(limiters))
	}
}

func TestBuildLimiters_PerConnOnly(t *testing.T) {
	c := &Config{
		LimitConfig: LimitConfig{LimitPerConn: 50},
	}
	limiters := buildLimiters(c)
	if len(limiters) != 1 {
		t.Errorf("expected 1 limiter, got %d", len(limiters))
	}
	if limiters[0].GetLimit() != 50 {
		t.Errorf("expected per-conn limit 50, got %d", limiters[0].GetLimit())
	}
}

func TestBuildLimiters_GlobalAndPerConn(t *testing.T) {
	c := &Config{
		LimitConfig: LimitConfig{Limit: 100, LimitPerConn: 50},
	}
	c.InitRuntime().limiters = []*Limiter{NewLimiter(100)}
	limiters := buildLimiters(c)
	if len(limiters) != 2 {
		t.Errorf("expected 2 limiters, got %d", len(limiters))
	}
}

// --- Wrapper chain traversal tests ---

func TestWrapperChain_Unwrap(t *testing.T) {
	mc := newMockConn()
	bc := newBaseConn(mc, nil)

	// Test GetTCPConn
	found, err := GetTCPConn(bc)
	if err != nil {
		t.Fatalf("GetTCPConn failed on bare BaseConn: %v", err)
	}
	if found != bc {
		t.Error("GetTCPConn should return the BaseConn itself")
	}

	// Test GetTCPConn through RemainConn
	rc := &RemainConn{Conn: bc}
	found, err = GetTCPConn(rc)
	if err != nil {
		t.Fatalf("GetTCPConn through RemainConn failed: %v", err)
	}
	if found != bc {
		t.Error("GetTCPConn should unwrap through RemainConn")
	}

	// Test GetTCPConn through LimitConn
	lc := &LimitConn{Conn: rc}
	found, err = GetTCPConn(lc)
	if err != nil {
		t.Fatalf("GetTCPConn through LimitConn+RemainConn failed: %v", err)
	}
	if found != bc {
		t.Error("GetTCPConn should unwrap through LimitConn+RemainConn")
	}

	// Test GetInnerConn
	inner, err := GetInnerConn(lc)
	if err != nil {
		t.Fatalf("GetInnerConn failed: %v", err)
	}
	if _, ok := inner.(*RemainConn); !ok {
		t.Errorf("GetInnerConn should return RemainConn, got %T", inner)
	}
}

func TestGetConn_ConvertsRawConn(t *testing.T) {
	mc := newMockConn()
	// raw net.Conn should be wrapped in BaseConn by GetConn
	result := GetConn(mc)
	bc, ok := result.(*BaseConn)
	if !ok {
		t.Fatalf("GetConn should wrap raw net.Conn in BaseConn, got %T", result)
	}
	if bc.GetCfg() != nil {
		t.Error("GetConn with nil config should have nil cfg")
	}
}

func TestGetConn_PreservesExistingConn(t *testing.T) {
	mc := newMockConn()
	cfg := &Config{CryptoConfig: CryptoConfig{Method: "aes-256-gcm"}}
	bc := newBaseConn(mc, cfg)

	result := GetConn(bc)
	if result != bc {
		t.Error("GetConn should not re-wrap existing Conn")
	}
}

// --- End-to-end wrapper chain test ---

func TestWrapperChain_ReadWriteRoundtrip(t *testing.T) {
	// Build client-side chain: BaseConn -> (mock)
	mc := newMockConn()
	mc.setReadData([]byte("response-data"))

	cfg := &Config{
		CryptoConfig: CryptoConfig{Method: "aes-256-gcm", Password: "test"},
	}

	// Build a typical chain: BaseConn -> RemainConn
	bc := newBaseConn(mc, cfg)
	bc.SetDst(&SockAddr{Hdr: []byte{1, 0, 0, 0, 0, 0, 80}})

	// Wrap with RemainConn (simulating pre-read data)
	rc := &RemainConn{Conn: bc}

	// Write through the chain
	testData := []byte("hello-world")
	n, err := rc.Write(testData)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != len(testData) {
		t.Errorf("expected %d bytes written, got %d", len(testData), n)
	}

	// Verify data reached the mock
	written := mc.getWritten()
	if string(written) != "hello-world" {
		t.Errorf("expected 'hello-world', got '%s'", string(written))
	}

	// Read through the chain
	buf := make([]byte, 32)
	n, err = rc.Read(buf)
	if err != nil {
		t.Fatalf("Read failed: %v", err)
	}
	if n != 13 || string(buf[:n]) != "response-data" {
		t.Errorf("expected 'response-data', got '%s'", string(buf[:n]))
	}
}

// Test Remaining Data buffering in RemainConn
func TestRemainConn_BufferOverflow(t *testing.T) {
	mc := newMockConn()
	remain := []byte("data-that-does-not-fit-in-small-buffer")
	mc.setReadData([]byte("-overflow"))
	bc := newBaseConn(mc, nil)

	rc := &RemainConn{Conn: bc, remain: remain}

	// Read with a tiny buffer
	buf := make([]byte, 4)
	n, err := rc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(buf[:n]) != "data" {
		t.Errorf("first tiny read: got '%s'", buf[:n])
	}

	// Second tiny read
	n, err = rc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(buf[:n]) != "-tha" {
		t.Errorf("second tiny read: got '%s'", buf[:n])
	}

	// Third read: consume remaining cached data
	bigBuf := make([]byte, 128)
	n, err = rc.Read(bigBuf)
	if err != nil {
		t.Fatal(err)
	}
	expected1 := "t-does-not-fit-in-small-buffer"
	if string(bigBuf[:n]) != expected1 {
		t.Errorf("third read: got '%s', want '%s'", string(bigBuf[:n]), expected1)
	}

	// Fourth read: cached data exhausted, reads from underlying conn
	n, err = rc.Read(bigBuf)
	if err != nil {
		t.Fatal(err)
	}
	expected2 := "-overflow"
	if string(bigBuf[:n]) != expected2 {
		t.Errorf("fourth read: got '%s', want '%s'", string(bigBuf[:n]), expected2)
	}
}

// --- SS2022 roundtrip integration test ---

func testSS2022Exchange(t *testing.T, doReverse bool) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	method := "2022-blake3-aes-256-gcm"
	password := "UNju0cW7b0VTf2c+zCRCX+rL+5fTAFarbqQwfjrEVZw="

	cfg := &Config{
		CryptoConfig: CryptoConfig{
			Method:   method,
			Password: password,
			Ivlen:    32,
		},
	}

	psk, err := crypto.DecodePSK(password, 32)
	if err != nil {
		t.Fatalf("decode PSK: %v", err)
	}

	// Connect client
	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	// Client sends header
	salt := []byte("0123456789abcdef0123456789abcdef")
	ciph, _ := crypto.NewTcpCipher2022(cfg.Method, psk, salt)
	addr := &SockAddr{Hdr: []byte{1, 127, 0, 0, 1, 0, 80}}
	header := buildAead2022Header(ciph, salt, addr, nil)
	_, err = rawClient.Write(header)
	if err != nil {
		t.Fatal(err)
	}

	// Accept server side
	rawServer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}

	// Server reads header
	buf := make([]byte, 4096)
	io.ReadFull(rawServer, buf[:32])
	cliSalt := make([]byte, 32)
	copy(cliSalt, buf[:32])
	serverCiph, _ := crypto.NewTcpCipher2022(cfg.Method, psk, cliSalt)
	hdr1Len := 1 + 8 + 2 + serverCiph.Overhead()
	io.ReadFull(rawServer, buf[:hdr1Len])
	hdr1 := make([]byte, hdr1Len)
	copy(hdr1, buf[:hdr1Len])
	serverCiph.DecryptPacket(hdr1)
	addrLen := int(uint16(hdr1[9])<<8 | uint16(hdr1[10]))
	hdr2Len := addrLen + serverCiph.Overhead()
	io.ReadFull(rawServer, buf[:hdr2Len])
	hdr2 := make([]byte, hdr2Len)
	copy(hdr2, buf[:hdr2Len])
	serverCiph.DecryptPacket(hdr2)

	svSalt := make([]byte, 32)
	sConn := newCryptoConn(newBaseConn(rawServer, cfg), newServerAead2022Codec(method, psk, svSalt, cliSalt, serverCiph))
	clientAead := newCryptoConn(newBaseConn(rawClient, cfg), newClientAead2022Codec(method, psk, ciph))
	defer sConn.Close()
	defer clientAead.Close()

	// Client to server
	for i, payload := range []string{"hello", "another test message", "!", "final"} {
		if _, err := clientAead.Write([]byte(payload)); err != nil {
			t.Fatalf("payload %d write: %v", i, err)
		}
		buf := make([]byte, 256)
		n, err := sConn.Read(buf)
		if err != nil {
			t.Fatalf("payload %d read: %v", i, err)
		}
		if string(buf[:n]) != payload {
			t.Errorf("payload %d: got '%s', want '%s'", i, string(buf[:n]), payload)
		}
	}

	if doReverse {
		// Server to client (exercises handshake)
		go sConn.Write([]byte("response-from-server"))
		buf := make([]byte, 256)
		n, err := clientAead.Read(buf)
		if err != nil {
			t.Fatalf("reverse read: %v", err)
		}
		if string(buf[:n]) != "response-from-server" {
			t.Errorf("reverse: got '%s'", string(buf[:n]))
		}
	}
}

func TestAEAD2022Roundtrip(t *testing.T) {
	testSS2022Exchange(t, true)
}

// Test concurrent read/write safety (regression test for aead2022.go buffer fix)
func TestAEAD2022ConcurrentReadWrite(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	method := "2022-blake3-aes-256-gcm"
	password := "UNju0cW7b0VTf2c+zCRCX+rL+5fTAFarbqQwfjrEVZw="
	psk, err := crypto.DecodePSK(password, 32)
	if err != nil {
		t.Fatalf("decode PSK: %v", err)
	}

	cfg := &Config{
		CryptoConfig: CryptoConfig{
			Method:   method,
			Password: password,
			Ivlen:    32,
		},
	}

	rawClient, _ := net.Dial("tcp", ln.Addr().String())
	salt := []byte("c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0")
	ciph, _ := crypto.NewTcpCipher2022(cfg.Method, psk, salt)
	addr := &SockAddr{Hdr: []byte{1, 127, 0, 0, 1, 0, 80}}
	rawClient.Write(buildAead2022Header(ciph, salt, addr, nil))

	rawServer, _ := ln.Accept()
	buf := make([]byte, 4096)
	io.ReadFull(rawServer, buf[:32])
	cliSalt := make([]byte, 32)
	copy(cliSalt, buf[:32])
	serverCiph, _ := crypto.NewTcpCipher2022(cfg.Method, psk, cliSalt)
	hdr1Len := 1 + 8 + 2 + serverCiph.Overhead()
	io.ReadFull(rawServer, buf[:hdr1Len])
	hdr1 := make([]byte, hdr1Len)
	copy(hdr1, buf[:hdr1Len])
	serverCiph.DecryptPacket(hdr1)
	addrLen := int(uint16(hdr1[9])<<8 | uint16(hdr1[10]))
	hdr2Len := addrLen + serverCiph.Overhead()
	io.ReadFull(rawServer, buf[:hdr2Len])
	hdr2 := make([]byte, hdr2Len)
	copy(hdr2, buf[:hdr2Len])
	serverCiph.DecryptPacket(hdr2)

	svSalt := make([]byte, 32)
	serverAead := newCryptoConn(newBaseConn(rawServer, cfg), newServerAead2022Codec(method, psk, svSalt, cliSalt, serverCiph))
	clientAead := newCryptoConn(newBaseConn(rawClient, cfg), newClientAead2022Codec(method, psk, ciph))
	defer clientAead.Close()
	defer serverAead.Close()

	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if _, err := serverAead.Write([]byte("server-data-chunk")); err != nil {
				errCh <- err
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		for i := 0; i < 100; i++ {
			if _, err := serverAead.Read(buf); err != nil {
				errCh <- err
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if _, err := clientAead.Write([]byte("client-data-chunk")); err != nil {
				errCh <- err
				return
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 256)
		for i := 0; i < 100; i++ {
			if _, err := clientAead.Read(buf); err != nil {
				errCh <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)

	for e := range errCh {
		t.Error(e)
	}
}
