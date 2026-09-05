package ss

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

var tlsObfsPayload = func() []byte {
	b := make([]byte, 65568) // Pipe's read size: past the 16-bit record cap
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}()

// readTLSRecord reads one 5-byte record header plus its body.
func readTLSRecord(t *testing.T, r io.Reader) (typ byte, body []byte) {
	t.Helper()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		t.Fatal(err)
	}
	l := int(binary.BigEndian.Uint16(hdr[3:5]))
	if l == 0 {
		t.Fatalf("zero-length record (truncated length field?)")
	}
	body = make([]byte, l)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatal(err)
	}
	return hdr[0], body
}

// TestSimpleTLSConnLargeServerWrite pins that a server first write larger
// than one TLS record is split instead of truncating the 16-bit length field
// in GenTLSServerHello, which silently desynced the peer's record layer.
func TestSimpleTLSConnLargeServerWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	srv := &SimpleTLSConn{Conn: AsNetConn(c1), srvresp: true, sessionID: utils.GetRandomBytes(32)}

	done := make(chan error, 1)
	go func() {
		_, err := srv.Write(tlsObfsPayload)
		done <- err
	}()

	// Records 1-2: ServerHello + CCS.
	typ, _ := readTLSRecord(t, c2)
	if typ != 0x16 {
		t.Fatalf("record 1 type = %#x, want 0x16", typ)
	}
	typ, _ = readTLSRecord(t, c2)
	if typ != 0x14 {
		t.Fatalf("record 2 type = %#x, want 0x14", typ)
	}

	var got []byte
	for len(got) < len(tlsObfsPayload) {
		typ, body := readTLSRecord(t, c2)
		if typ != 0x16 && typ != 0x17 {
			t.Fatalf("payload record type = %#x", typ)
		}
		got = append(got, body...)
	}
	if !bytes.Equal(got, tlsObfsPayload) {
		t.Fatal("server payload corrupted across record split")
	}
	if err := <-done; err != nil {
		t.Fatalf("server Write: %v", err)
	}
}

// TestSimpleTLSConnLargeClientWrite pins the client-side equivalent: the
// payload bundled into the ClientHello's session ticket is capped below the
// server's 16389-byte handshake sniff limit and the remainder goes out as
// application-data records.
func TestSimpleTLSConnLargeClientWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	cli := &SimpleTLSConn{Conn: AsNetConn(c1), clireq: true, host: "example.com"}

	done := make(chan error, 1)
	go func() {
		_, err := cli.Write(tlsObfsPayload)
		done <- err
	}()

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c2, hdr); err != nil {
		t.Fatal(err)
	}
	if hdr[0] != 0x16 {
		t.Fatalf("record 1 type = %#x, want 0x16", hdr[0])
	}
	helloLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if helloLen > 16389 {
		t.Fatalf("ClientHello record is %d bytes; server sniffer rejects >16389", helloLen)
	}
	full := make([]byte, 5+helloLen)
	copy(full, hdr)
	if _, err := io.ReadFull(c2, full[5:]); err != nil {
		t.Fatal(err)
	}
	ok, _, msg := utils.ParseTLSClientHelloMsg(full)
	if !ok || msg == nil {
		t.Fatal("server-side ClientHello parse failed on generated record")
	}

	var got []byte
	got = append(got, msg.SessionTicket...)
	for len(got) < len(tlsObfsPayload) {
		typ, body := readTLSRecord(t, c2)
		if typ != 0x17 {
			t.Fatalf("data record type = %#x, want 0x17", typ)
		}
		got = append(got, body...)
	}
	if !bytes.Equal(got, tlsObfsPayload) {
		t.Fatal("client payload corrupted across ticket/data split")
	}
	if err := <-done; err != nil {
		t.Fatalf("client Write: %v", err)
	}
}

// scriptConn returns one chunk per Read, standing in for fragmented TCP reads.
type scriptConn struct {
	chunks  [][]byte
	idx     int
	mu      sync.Mutex
	written []byte
}

func (c *scriptConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idx >= len(c.chunks) {
		return 0, io.EOF
	}
	n := copy(b, c.chunks[c.idx])
	c.idx++
	return n, nil
}

func (c *scriptConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.written = append(c.written, b...)
	return len(b), nil
}

func (c *scriptConn) Close() error                       { return nil }
func (c *scriptConn) LocalAddr() net.Addr                { return nil }
func (c *scriptConn) RemoteAddr() net.Addr               { return nil }
func (c *scriptConn) SetDeadline(_ time.Time) error      { return nil }
func (c *scriptConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *scriptConn) SetWriteDeadline(_ time.Time) error { return nil }

const obfsTestReqHdr = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"

// TestObfsEOSDataNotDropped pins the pendingEOF fix: payload bytes returned in
// the same Read that consumes the "0\r\n\r\n" terminator must be delivered,
// with the end of stream surfacing on the NEXT read.
func TestObfsEOSDataNotDropped(t *testing.T) {
	raw := &scriptConn{chunks: [][]byte{
		[]byte(obfsTestReqHdr + "5\r\nhello\r\n0\r\n\r\n"),
	}}
	c := NewObfsConn(newBaseConn(raw, nil))
	c.resp = true

	buf := make([]byte, 128)
	segs, err := c.Read(buf, nil)
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if string(segs[0]) != "hello" {
		t.Fatalf("first read = %q, want hello", segs[0])
	}
	if _, err := c.Read(buf, nil); err == nil {
		t.Fatal("second read must report the end of stream")
	}
}

// TestObfsFragmentedHeader pins the incremental header parse: a request
// header split across TCP segments must be accumulated, not rejected.
func TestObfsFragmentedHeader(t *testing.T) {
	raw := &scriptConn{chunks: [][]byte{
		[]byte("POST / HT"),
		[]byte(obfsTestReqHdr[len("POST / HT"):]),
		[]byte("5\r\nhello\r\n"),
	}}
	c := NewObfsConn(newBaseConn(raw, nil))
	c.resp = true

	buf := make([]byte, 128)
	segs, err := c.Read(buf, nil)
	if err != nil {
		t.Fatalf("fragmented header rejected: %v", err)
	}
	if string(segs[0]) != "hello" {
		t.Fatalf("payload = %q, want hello", segs[0])
	}
}

// TestObfsChunkLenCap pins the chunked-encoding length bound: a huge hex
// chunk length errors out instead of overflowing int (which used to panic on
// b2[:negative]) — reachable before any authentication.
func TestObfsChunkLenCap(t *testing.T) {
	raw := &scriptConn{chunks: [][]byte{
		[]byte(obfsTestReqHdr),
		[]byte("ffffffffffffffff\r\n"),
	}}
	c := NewObfsConn(newBaseConn(raw, nil))
	c.resp = true

	buf := make([]byte, 128)
	_, err := c.Read(buf, nil)
	if err == nil {
		t.Fatal("oversized chunk length must error")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v, want chunk-length-too-large", err)
	}
}

// blockingConn blocks its first Read until proceed is closed and ignores
// Close, so a Close racing an in-flight Read can be interleaved
// deterministically.
type blockingConn struct {
	Conn
	started chan struct{}
	proceed chan struct{}
	data    []byte
}

func (c *blockingConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	close(c.started)
	<-c.proceed
	n := copy(buf, c.data)
	return [][]byte{buf[:n]}, nil
}

func (c *blockingConn) Write(bufs ...[]byte) (int, error) { return 0, nil }
func (c *blockingConn) Close() error                      { return nil }

// TestSimpleHTTPConnParserBufferNotPooled pins the response-header parser
// buffer lifetime: it must stay heap-owned, because Close runs on the
// opposite Pipe direction and returning a pooled buffer while Read may still
// be parsing into it hands the same memory to another connection.
func TestSimpleHTTPConnParserBufferNotPooled(t *testing.T) {
	stub := &blockingConn{started: make(chan struct{}), proceed: make(chan struct{})}
	conn := &SimpleHTTPConn{Conn: stub, resp: true}

	type result struct {
		segs [][]byte
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		segs, err := conn.Read(make([]byte, 16), nil)
		resCh <- result{segs, err}
	}()
	<-stub.started // parser created; Read is blocked inside stub.Read

	conn.parserMu.Lock()
	pbuf := conn.parser.GetBuf()
	conn.parserMu.Unlock()
	if cap(pbuf) != buffersize {
		t.Fatalf("parser buffer cap = %d, want %d (heap-owned, not a pool class)", cap(pbuf), buffersize)
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		b := utils.GetBuf(buffersize)
		if len(b) > 0 && &b[0] == &pbuf[0] {
			t.Fatal("parser buffer was recycled through the shared pool after Close")
		}
		utils.PutBuf(b)
	}

	stub.data = []byte("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\npayload")
	close(stub.proceed)
	if r := <-resCh; r.err != nil {
		t.Fatalf("read after Close failed: %v", r.err)
	}
}
