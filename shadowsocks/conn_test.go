package ss

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

// --- mock connection for testing ---

type mockConn struct {
	readBuf    []byte
	readPos    int
	writeBuf   []byte
	closed     bool
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
	n, err := bc.Write(bufs[0], bufs[1])
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
	n, err := bc.Write([]byte("part1-"), []byte("part2"))
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
	n, err := ReadN(rc, buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(buf[:n]) != "cache" {
		t.Errorf("first read: got %d bytes '%s', want 5 bytes 'cache'", n, buf[:n])
	}

	// Second read should get remainder of remain
	n, err = ReadN(rc, buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 || string(buf[:n]) != "d-dat" {
		t.Errorf("second read: got %d bytes '%s', want 5 bytes 'd-dat'", n, buf[:n])
	}

	// Third read: last byte of remain
	n, err = ReadN(rc, buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || string(buf[:n]) != "a" {
		t.Errorf("third read: got %d bytes '%s', want 1 byte 'a'", n, buf[:n])
	}

	// Fourth read: remain exhausted, reads from underlying conn
	n, err = ReadN(rc, buf, nil)
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
	n, err := ReadN(rc, buf, nil)
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
	_, err = rc.Write([]byte("more"))
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

	n, err := rc.Write([]byte("hello"), []byte("-world"))
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
	n, err := ReadN(lc, buf, nil)
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
	n, err = ReadN(rc, buf, nil)
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
	n, err := ReadN(rc, buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(buf[:n]) != "data" {
		t.Errorf("first tiny read: got '%s'", buf[:n])
	}

	// Second tiny read
	n, err = ReadN(rc, buf, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || string(buf[:n]) != "-tha" {
		t.Errorf("second tiny read: got '%s'", buf[:n])
	}

	// Third read: consume remaining cached data
	bigBuf := make([]byte, 128)
	n, err = ReadN(rc, bigBuf, nil)
	if err != nil {
		t.Fatal(err)
	}
	expected1 := "t-does-not-fit-in-small-buffer"
	if string(bigBuf[:n]) != expected1 {
		t.Errorf("third read: got '%s', want '%s'", string(bigBuf[:n]), expected1)
	}

	// Fourth read: cached data exhausted, reads from underlying conn
	n, err = ReadN(rc, bigBuf, nil)
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
	sConn := newServerCryptoConn2022(newBaseConn(rawServer, cfg), method, psk, svSalt, cliSalt, serverCiph)
	clientAead := newClientCryptoConn2022(newBaseConn(rawClient, cfg), method, psk, ciph)
	defer sConn.Close()
	defer clientAead.Close()

	// Client to server
	for i, payload := range []string{"hello", "another test message", "!", "final"} {
		if _, err := clientAead.Write([]byte(payload)); err != nil {
			t.Fatalf("payload %d write: %v", i, err)
		}
		buf := make([]byte, 256)
		n, err := ReadN(sConn, buf, nil)
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
		n, err := ReadN(clientAead, buf, nil)
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

func TestAEAD2022LargePayload(t *testing.T) {
	testAEAD2022Large(t, 65536)  // exactly 64KB, single frame
	testAEAD2022Large(t, 131072) // 128KB, requires 2 frames (splitting)
}

func testAEAD2022Large(t *testing.T, size int) {
	t.Helper()
	psk := []byte("0123456789abcdef0123456789abcdef")
	method := "2022-blake3-aes-256-gcm"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		rawClient, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Error(err)
			return
		}
		defer rawClient.Close()

		// Send client header (salt + encrypted header)
		salt := make([]byte, 32)
		for i := range salt {
			salt[i] = byte(i)
		}
		ciph, _ := crypto.NewTcpCipher2022(method, psk, salt)
		addr := &SockAddr{Hdr: []byte{1, 127, 0, 0, 1, 0, 80}}
		header := buildAead2022Header(ciph, salt, addr, nil)
		if _, err := rawClient.Write(header); err != nil {
			t.Error(err)
			return
		}

		// Let the codec handle the server handshake via doServerHandshake.
		clientAead := newClientCryptoConn2022(newBaseConn(rawClient, nil), method, psk, ciph)

		// Read the handshake greeting ("ok")
		greeting := make([]byte, 2)
		if _, err := ReadN(clientAead, greeting, nil); err != nil {
			t.Errorf("read greeting: %v", err)
			return
		}

		// Round-trip: send large payload, read echo
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i%251 + 1) // non-zero pattern
		}
		if _, err := clientAead.Write(payload); err != nil {
			t.Errorf("write %d bytes: %v", size, err)
			return
		}
		echo := make([]byte, size)
		for off := 0; off < len(echo); {
			n, err := ReadN(clientAead, echo[off:], nil)
			if err != nil {
				t.Errorf("read echo %d bytes (offset %d): %v", size, off, err)
				return
			}
			if n == 0 {
				break
			}
			off += n
		}
		for i := range echo {
			if echo[i] != payload[i] {
				t.Errorf("mismatch at byte %d: %d != %d", i, echo[i], payload[i])
				return
			}
		}
	}()

	// Server side
	rawServer, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer rawServer.Close()

	// Read client header and create server codec
	cliSalt, serverCiph := readClientHeader(t, rawServer, psk, method)

	svSalt := make([]byte, 32)
	sConn := newServerCryptoConn2022(newBaseConn(rawServer, nil), method, psk, svSalt, cliSalt, serverCiph)
	sConn.DeferClose()
	defer sConn.Close()

	// Write a small message first to trigger the server handshake
	if _, err := sConn.Write([]byte("ok")); err != nil {
		t.Fatalf("server handshake write: %v", err)
	}

	// Read large payload and echo via CryptoConn
	recv := make([]byte, size)
	for off := 0; off < len(recv); {
		n, err := ReadN(sConn, recv[off:], nil)
		if err != nil {
			t.Fatalf("server read %d bytes (offset %d): %v", size, off, err)
		}
		if n == 0 {
			break
		}
		off += n
	}
	if _, err := sConn.Write(recv); err != nil {
		t.Fatalf("server write echo %d bytes: %v", size, err)
	}

	wg.Wait()
}

// readClientHeader parses the raw 2022 client header from the connection.
func readClientHeader(t *testing.T, conn net.Conn, psk []byte, method string) (cliSalt []byte, ciph *crypto.TcpCipher2022) {
	t.Helper()
	buf := make([]byte, 4096)
	if _, err := io.ReadFull(conn, buf[:32]); err != nil {
		t.Fatalf("read client salt: %v", err)
	}
	cliSalt = make([]byte, 32)
	copy(cliSalt, buf[:32])

	ciph, err := crypto.NewTcpCipher2022(method, psk, cliSalt)
	if err != nil {
		t.Fatalf("NewTcpCipher2022: %v", err)
	}

	hdr1Len := 1 + 8 + 2 + ciph.Overhead()
	if _, err := io.ReadFull(conn, buf[:hdr1Len]); err != nil {
		t.Fatalf("read client hdr1: %v", err)
	}
	hdr1 := make([]byte, hdr1Len)
	copy(hdr1, buf[:hdr1Len])
	var ok bool
	hdr1, ok = ciph.DecryptPacket(hdr1)
	if !ok {
		t.Fatal("decrypt client hdr1 failed")
	}

	addrLen := int(uint16(hdr1[9])<<8 | uint16(hdr1[10]))
	hdr2Len := addrLen + ciph.Overhead()
	if _, err := io.ReadFull(conn, buf[:hdr2Len]); err != nil {
		t.Fatalf("read client hdr2: %v", err)
	}
	hdr2 := make([]byte, hdr2Len)
	copy(hdr2, buf[:hdr2Len])
	_, ok = ciph.DecryptPacket(hdr2)
	if !ok {
		t.Fatal("decrypt client hdr2 failed")
	}
	return
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
	serverAead := newServerCryptoConn2022(newBaseConn(rawServer, cfg), method, psk, svSalt, cliSalt, serverCiph)
	clientAead := newClientCryptoConn2022(newBaseConn(rawClient, cfg), method, psk, ciph)
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
			if _, err := ReadN(serverAead, buf, nil); err != nil {
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
			if _, err := ReadN(clientAead, buf, nil); err != nil {
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

// --- DeferClose tests ---

func TestDeferClose_DelaysClose(t *testing.T) {
	server, _ := net.Pipe()

	cc := newCryptoConnStream(newBaseConn(server, nil), nil, nil)
	cc.DeferClose()

	start := time.Now()
	cc.Close()
	elapsed := time.Since(start)

	// Close() should return immediately (it spawns a goroutine for the delay)
	if elapsed > 50*time.Millisecond {
		t.Errorf("Close() took %v, expected immediate return (deferred to goroutine)", elapsed)
	}

	// net.Pipe: if client end is closed, Read on server returns ErrClosedPipe.
	// If client end is NOT closed, Read blocks until timeout.
	// After DeferClose, client.Close is scheduled in 8-71s, so Read should
	// block (conn still alive) and hit the deadline.
	server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := server.Read(buf)

	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		t.Log("read timed out — pipe still open, DeferClose working")
	} else if err != nil {
		t.Errorf("underlying conn saw close too early: %v (expected timeout)", err)
	}
}

func TestDeferClose_NoDeferClosesImmediately(t *testing.T) {
	server, _ := net.Pipe()

	cc := newCryptoConnStream(newBaseConn(server, nil), nil, nil)

	cc.Close()

	// net.Pipe: when client end is closed, server Read returns ErrClosedPipe
	server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := server.Read(buf)
	if err == nil {
		t.Error("underlying conn still open, expected it to be closed")
	} else if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		t.Error("read timed out — conn should be closed, not just idle")
	}
}

// oversizedMockConn is a minimal Conn that returns data larger than the read
// buffer, triggering the connReader's oversized-data buffering path.
type oversizedMockConn struct {
	data      []byte
	readCalls int
	mu        sync.Mutex
}

func (m *oversizedMockConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.readCalls++
	if m.readCalls > 1 {
		return nil, io.EOF
	}
	// Return data larger than buf — connReader must buffer the excess.
	return [][]byte{m.data}, nil
}

func (m *oversizedMockConn) Write(bufs ...[]byte) (int, error)  { return 0, nil }
func (m *oversizedMockConn) Close() error                       { return nil }
func (m *oversizedMockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *oversizedMockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *oversizedMockConn) SetDeadline(t time.Time) error      { return nil }
func (m *oversizedMockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *oversizedMockConn) SetWriteDeadline(t time.Time) error { return nil }

// TestReadN_ConnReaderDataLoss demonstrates that ReadN silently drops data
// when the underlying Conn returns more data than fits in the read buffer.
//
// Root cause: each ReadN call creates a new connReader via AsReader. If a
// previous connReader buffered excess data (from oversized or multi-segment
// results), that buffer is discarded on the next call — the new connReader
// reads fresh from the Conn, permanently skipping the buffered bytes.
func TestReadN_ConnReaderDataLoss(t *testing.T) {
	fullData := make([]byte, 100)
	for i := range fullData {
		fullData[i] = byte(i)
	}

	mc := &oversizedMockConn{data: fullData}

	// Use a small buffer so connReader must buffer excess.
	smallBuf := make([]byte, 10)

	// First ReadN: only 10 bytes fit, remaining 90 buffered in connReader.buf.
	n, err := ReadN(mc, smallBuf, nil)
	if err != nil {
		t.Fatalf("first ReadN: %v", err)
	}
	if n != 10 {
		t.Fatalf("first ReadN: got %d bytes, want 10", n)
	}
	for i := 0; i < 10; i++ {
		if smallBuf[i] != fullData[i] {
			t.Fatalf("first ReadN: wrong byte at %d: got %d, want %d", i, smallBuf[i], fullData[i])
		}
	}

	// BUG: ReadN creates a new connReader. The 90 buffered bytes are lost.
	// The new connReader calls mc.Read again, which now returns EOF.
	n, err = ReadN(mc, smallBuf, nil)
	if err != io.EOF {
		t.Errorf("second ReadN: got err=%v, want io.EOF (connReader lost buffered data and called Read again)", err)
	}
	if n != 0 {
		t.Errorf("second ReadN: got %d bytes, want 0 (connReader should have been drained via EOF)", n)
	}

	// The underlying conn was called twice (once per ReadN) instead of once.
	if mc.readCalls != 2 {
		t.Errorf("readCalls=%d, want 2 (Read was called again instead of draining buffer)", mc.readCalls)
	}

	// Total data received: 10 bytes out of 100. 90 bytes silently lost.
	t.Log("BUG CONFIRMED: 90/100 bytes silently lost due to connReader recreation in ReadN")
}

// TestReadN_ConnReaderReused shows the correct behavior when connReader is
// reused across ReadN calls — no data is lost.
func TestReadN_ConnReaderReused(t *testing.T) {
	fullData := make([]byte, 100)
	for i := range fullData {
		fullData[i] = byte(i)
	}

	mc := &oversizedMockConn{data: fullData}

	// Reuse the same connReader across reads — the fix approach.
	r := AsReader(mc, nil)
	smallBuf := make([]byte, 10)

	totalRead := 0
	for totalRead < len(fullData) {
		n, err := r.Read(smallBuf)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read at offset %d: %v", totalRead, err)
		}
		for i := 0; i < n; i++ {
			if smallBuf[i] != fullData[totalRead+i] {
				t.Fatalf("wrong byte at offset %d: got %d, want %d", totalRead+i, smallBuf[i], fullData[totalRead+i])
			}
		}
		totalRead += n
	}

	if totalRead != 100 {
		t.Errorf("totalRead=%d, want 100", totalRead)
	}
	if mc.readCalls != 1 {
		t.Errorf("readCalls=%d, want 1 (buffered data served without re-reading)", mc.readCalls)
	}
	t.Log("OK: all 100 bytes received, underlying Read called only once")
}

// TestCryptoConnStream_InnerConnReaderReused verifies that the inner
// connReader is now persistent across cryptoConnStream.Read calls.
// Previously, a new AsReader was created per call, causing buffered data loss.
func TestCryptoConnStream_InnerConnReaderReused(t *testing.T) {
	rawData := make([]byte, 200)
	for i := range rawData {
		rawData[i] = byte(i)
	}
	inner := &oversizedMockConn{data: rawData}

	enc, _ := crypto.NewPlainEncrypter(nil, nil)
	dec, _ := crypto.NewPlainDecrypter(nil, 0)

	cc := newCryptoConnStream(inner, enc, dec)

	// Read all data in small chunks. The persistent inner reader should
	// buffer excess and serve it on subsequent calls without re-reading.
	smallBuf := make([]byte, 10)
	totalRead := 0
	for totalRead < len(rawData) {
		segs, err := cc.Read(smallBuf, nil)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read at offset %d: %v", totalRead, err)
		}
		for _, s := range segs {
			for j, b := range s {
				exp := byte(totalRead + j)
				if b != exp {
					t.Errorf("byte at offset %d: got %d, want %d", totalRead+j, b, exp)
				}
			}
			totalRead += len(s)
		}
	}

	if totalRead != 200 {
		t.Errorf("totalRead=%d, want 200", totalRead)
	}
	if inner.readCalls != 1 {
		t.Errorf("inner readCalls=%d, want 1 (persistent reader should not re-read)", inner.readCalls)
	}
	t.Log("OK: persistent inner connReader, all 200 bytes received, inner conn read once")
}

// TestCryptoConnStream_ReadWithExactBuffer tests that data is NOT lost when
// connReader doesn't need to buffer — i.e., when ReadFrame output fits in
// the caller's buffer. This is the common case in production.
func TestCryptoConnStream_ReadWithExactBuffer(t *testing.T) {
	// Use net.Pipe to get real TCP-like behavior with BaseConn.
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	enc, _ := crypto.NewPlainEncrypter(nil, nil)
	dec, _ := crypto.NewPlainDecrypter(nil, 0)

	serverConn := newCryptoConnStream(newBaseConn(serverRaw, nil), enc, dec)

	// Write known data from client side, then close to unblock server reads.
	testData := []byte("hello world from the other side of the pipe")
	go func() {
		clientRaw.Write(testData)
		clientRaw.Close()
	}()

	// Read with a buffer larger than data — no buffering needed.
	buf := make([]byte, 1024)
	n, err := ReadN(serverConn, buf, nil)
	if err != nil {
		t.Fatalf("ReadN: %v", err)
	}
	if n != len(testData) {
		t.Errorf("got %d bytes, want %d", n, len(testData))
	}
	if string(buf[:n]) != string(testData) {
		t.Errorf("data mismatch: got %q, want %q", buf[:n], testData)
	}

	// Second read should get EOF (client closed)
	n, err = ReadN(serverConn, buf, nil)
	if err != io.EOF {
		t.Errorf("second ReadN: got err=%v n=%d, want io.EOF", err, n)
	}
}

// TestReadN_MultiReadCalls verifies data integrity across multiple ReadN calls
// when using a real crypto connection. Each ReadN creates a new connReader —
// if the inner connReader in cryptoConnStream drops data, this test catches it.
func TestReadN_MultiReadCallsDataIntegrity(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()

	// Use a real AEAD cipher so the cryptoConnStream read path is fully exercised.
	password := "testpassword"
	method := "aes-256-gcm"

	enc, err := crypto.NewEncrypter(method, password)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	dec, err := crypto.NewDecrypter(method, password)
	if err != nil {
		t.Fatalf("NewDecrypter: %v", err)
	}

	serverConn := newCryptoConnStream(newBaseConn(serverRaw, nil), enc, dec)

	// Write: 100 small writes from client, each encrypted separately.
	// Goal: produce many AEAD chunks so ReadFrame may return multi-chunk data.
	const numWrites = 50
	const payloadSize = 128
	totalSent := numWrites * payloadSize
	var sentData []byte

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer clientRaw.Close()
		clientEnc, _ := crypto.NewEncrypter(method, password)
		clientCC := newCryptoConnStream(newBaseConn(clientRaw, nil), clientEnc, nil)
		for i := 0; i < numWrites; i++ {
			chunk := make([]byte, payloadSize)
			for j := range chunk {
				chunk[j] = byte((i*payloadSize + j) % 251)
			}
			sentData = append(sentData, chunk...)
			if _, werr := clientCC.Write(chunk); werr != nil {
				t.Errorf("client write %d: %v", i, werr)
				return
			}
		}
	}()

	// Read using ReadN — each call creates a new connReader.
	// We use a small-ish buffer to increase chance of triggering buffering.
	buf := make([]byte, 512)
	var receivedData []byte
	for len(receivedData) < totalSent {
		n, rerr := ReadN(serverConn, buf, nil)
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			t.Fatalf("ReadN at offset %d: %v", len(receivedData), rerr)
		}
		receivedData = append(receivedData, buf[:n]...)
		if len(receivedData) > totalSent+1024 {
			t.Fatal("received more data than sent — loop guard")
		}
	}
	wg.Wait()

	if len(receivedData) != totalSent {
		t.Errorf("data length mismatch: got %d bytes, want %d", len(receivedData), totalSent)
	}
	for i := 0; i < len(receivedData) && i < len(sentData); i++ {
		if receivedData[i] != sentData[i] {
			t.Fatalf("data mismatch at byte %d: got %d, want %d (total received=%d, total sent=%d)",
				i, receivedData[i], sentData[i], len(receivedData), len(sentData))
		}
	}
	t.Logf("OK: %d bytes transferred correctly across %d ReadN calls", len(receivedData), numWrites)
}

func TestDeferClose_CancelRestoresImmediate(t *testing.T) {
	server, _ := net.Pipe()

	cc := newCryptoConnStream(newBaseConn(server, nil), nil, nil)
	cc.DeferClose()
	cc.CancelDeferClose()

	cc.Close()

	server.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	_, err := server.Read(buf)
	if err == nil {
		t.Error("underlying conn still open after CancelDeferClose + Close")
	} else if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		t.Error("read timed out — conn should be closed after CancelDeferClose")
	}
}

func TestDeferClose_FlagToggle(t *testing.T) {
	server, _ := net.Pipe()

	cc := newCryptoConnStream(newBaseConn(server, nil), nil, nil)
	cc.DeferClose()

	if !cc.deferClose {
		t.Error("DeferClose() did not set deferClose flag")
	}

	cc.CancelDeferClose()
	if cc.deferClose {
		t.Error("CancelDeferClose() did not clear deferClose flag")
	}
}
