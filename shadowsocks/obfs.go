package ss

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"encoding/binary"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
	"github.com/gorilla/websocket"
)

const (
	obfsParseChunkLen = iota
	obfsParseRN       = iota
	obfsParsePayload  = iota
	obfsParseRNR      = iota
	obfsParseRNRN     = iota
)

// maxObfsChunkLen bounds the parsed chunked-encoding length. Legitimate
// chunks never exceed one relay write (~64KB); without this cap the unbounded
// hex accumulation can overflow int to a negative value and panic on
// b2[:negative] — remotely reachable before any authentication.
const maxObfsChunkLen = 1 << 20

type ObfsConn struct {
	RemainConn
	resp bool
	req  bool
	// pendingEOF is set when payload bytes were returned in the same call in
	// which the closing "0\r\n\r\n" terminator was consumed; the next Read
	// reports the end of stream instead of silently dropping that data.
	pendingEOF bool
	chunkLen   int
	eos        bool // end of stream
	lock       sync.Mutex
	rlock      sync.Mutex
	wlock      sync.Mutex
	destroy    bool
	status     int
}

func (c *ObfsConn) Unwrap() Conn { return c.RemainConn.Conn }

func (c *ObfsConn) Close() (err error) {
	c.lock.Lock()
	if c.destroy {
		c.lock.Unlock()
		return
	}
	c.destroy = true
	c.lock.Unlock()

	// Best-effort graceful close: skip the terminating chunk when another
	// goroutine holds the write lock (it may be stalled writing to a dead
	// peer, and Close must not queue up behind it), and bound the write with
	// a deadline so a full TCP window can't park Close until the retransmit
	// timeout.
	if c.wlock.TryLock() {
		c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err = c.writeChunked(nil)
		c.SetWriteDeadline(time.Time{})
		c.wlock.Unlock()
		if err != nil {
			return c.RemainConn.Close()
		}
	}

	c.SetReadDeadline(time.Now())
	c.rlock.Lock()
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	for !c.eos {
		_, err = c.readInLock(buf)
		if err != nil {
			if c.eos {
				break
			}
			c.rlock.Unlock()
			return c.RemainConn.Close()
		}
	}
	c.rlock.Unlock()

	return c.RemainConn.Close()
}

func (c *ObfsConn) writeChunked(data []byte) (n int, err error) {
	n = len(data)
	header := fmt.Sprintf("%x\r\n", n)
	chunked := make([]byte, len(header)+n+2)
	copy(chunked, header)
	copy(chunked[len(header):], data)
	copy(chunked[len(header)+n:], "\r\n")
	_, err = c.RemainConn.Write(chunked)
	return
}

func (c *ObfsConn) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		n += len(b)
	}
	if n == 0 {
		return c.RemainConn.Write()
	}
	c.wlock.Lock()
	defer c.wlock.Unlock()
	if c.destroy {
		return 0, fmt.Errorf("write to closed connection")
	}
	_, err = c.writeChunked(flatten(bufs))
	return
}

func (c *ObfsConn) readObfsHeader(b []byte) (n int, err error) {
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err = ReadN(&c.RemainConn, buf, nil)
	if err != nil {
		return
	}
	if n == 0 {
		err = io.ErrUnexpectedEOF
		return
	}
	parser := utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
	defer utils.PutBuf(parser.GetBuf())
	// The header may be fragmented across TCP segments; keep feeding new
	// bytes (never re-feed, the parser accumulates internally) until it
	// reports a complete header instead of rejecting the first partial read.
	fed := 0
	for {
		ok, perr := parser.Read(buf[fed:n])
		if perr != nil {
			err = perr
			return
		}
		fed = n
		if ok {
			break
		}
		if n >= len(buf) {
			err = fmt.Errorf("obfs header too large from %s", c.RemoteAddr().String())
			return
		}
		var nn int
		nn, err = ReadN(&c.RemainConn, buf[n:], nil)
		if err != nil {
			return
		}
		if nn == 0 {
			err = io.ErrUnexpectedEOF
			return
		}
		n += nn
	}
	c.resp = false
	c.req = false
	remain := buf[parser.HeaderLen():n]
	if len(remain) != 0 {
		n = copy(b, remain)
		if n < len(remain) {
			c.remain = append(c.remain, remain[n:]...)
		}
	} else {
		n = 0
	}
	return
}

func (c *ObfsConn) doRead(b []byte) (n int, err error) {
	if c.req || c.resp {
		n, err = c.readObfsHeader(b)
		if err != nil || n != 0 {
			return
		}
	}
	return ReadN(&c.RemainConn, b, nil)
}

func (c *ObfsConn) readInLock(b []byte) (n int, err error) {
	if c.pendingEOF {
		// The terminator was consumed right after returning buffered payload;
		// the stream ends now.
		err = fmt.Errorf("read from closed obfsconn")
		return
	}
	if len(b) == 0 {
		return ReadN(&c.RemainConn, b, nil)
	}
	for n == 0 {
		var nr int
		nr, err = c.doRead(b)
		if err != nil {
			return
		}
		b2 := b[:nr]
		for len(b2) > 0 {
			if c.status == obfsParseChunkLen {
				if b2[0] >= '0' && b2[0] <= '9' {
					c.chunkLen = c.chunkLen*16 + int(b2[0]-'0')
					b2 = b2[1:]
					if c.chunkLen > maxObfsChunkLen {
						err = fmt.Errorf("obfs chunk length too large: %d", c.chunkLen)
						return
					}
				} else if b2[0] >= 'a' && b2[0] <= 'f' {
					c.chunkLen = c.chunkLen*16 + 10 + int(b2[0]-'a')
					b2 = b2[1:]
					if c.chunkLen > maxObfsChunkLen {
						err = fmt.Errorf("obfs chunk length too large: %d", c.chunkLen)
						return
					}
				} else if b2[0] == '\r' {
					c.status = obfsParseRN
					b2 = b2[1:]
				} else {
					err = fmt.Errorf("unexcepted length character %v", b2[0])
					return
				}
			} else if c.status == obfsParseRN {
				if b2[0] == '\n' {
					c.status = obfsParsePayload
					if c.chunkLen == 0 {
						c.eos = true
					}
					b2 = b2[1:]
				} else {
					err = fmt.Errorf("unexcepted length character %v", b2[0])
					return
				}
			} else if c.status == obfsParsePayload {
				if c.chunkLen == 0 {
					c.status = obfsParseRNR
					continue
				}
				var ncopy int
				if c.chunkLen > len(b2) {
					ncopy = len(b2)
				} else {
					ncopy = c.chunkLen
				}
				ncopy = copy(b[n:], b2[:ncopy])
				b2 = b2[ncopy:]
				n += ncopy
				c.chunkLen -= ncopy
				if c.chunkLen == 0 {
					c.status = obfsParseRNR
				}
				continue
			} else if c.status == obfsParseRNR {
				if b2[0] == '\r' {
					c.status = obfsParseRNRN
					b2 = b2[1:]
				} else {
					err = fmt.Errorf("unexcepted length character %v", b2[0])
					return
				}
			} else if c.status == obfsParseRNRN {
				if b2[0] == '\n' {
					c.status = obfsParseChunkLen
					b2 = b2[1:]
					if c.eos {
						if n > 0 {
							// Payload was already copied into b before the
							// terminator; return it now and report the end of
							// stream on the next read instead of dropping it.
							c.pendingEOF = true
							return
						}
						err = fmt.Errorf("read from closed obfsconn")
						return
					}
				} else {
					err = fmt.Errorf("unexcepted length character %v", b2[0])
					return
				}
			}
		}
	}
	return
}

func (c *ObfsConn) Read(buf []byte, pool *utils.BufPool) (segs [][]byte, err error) {
	c.rlock.Lock()
	defer c.rlock.Unlock()
	if c.destroy {
		err = fmt.Errorf("read from closed connection")
		return
	}
	n, err := c.readInLock(buf)
	if err != nil {
		return
	}
	return [][]byte{buf[:n]}, nil
}

func NewObfsConn(conn Conn) *ObfsConn {
	return &ObfsConn{RemainConn: RemainConn{Conn: conn}}
}

type RemainConn struct {
	Conn
	remain  []byte
	wremain []byte
}

func (c *RemainConn) Unwrap() Conn { return c.Conn }

func DecayRemainConn(conn Conn) Conn {
	rconn, ok := conn.(*RemainConn)
	if ok && len(rconn.remain) == 0 && len(rconn.wremain) == 0 {
		return rconn.Conn
	}
	return conn
}

func (c *RemainConn) Read(buf []byte, pool *utils.BufPool) (segs [][]byte, err error) {
	if len(c.remain) == 0 {
		return c.Conn.Read(buf, pool)
	}
	n := copy(buf, c.remain)
	if n == len(c.remain) {
		c.remain = nil
	} else {
		c.remain = c.remain[n:]
	}
	return [][]byte{buf[:n]}, nil
}

func (c *RemainConn) Write(bufs ...[]byte) (n int, err error) {
	if len(c.wremain) != 0 {
		for _, b := range bufs {
			n += len(b)
		}
		all := make([][]byte, 0, 1+len(bufs))
		all = append(all, c.wremain)
		all = append(all, bufs...)
		_, err = c.Conn.Write(all...)
		if err != nil {
			return
		}
		c.wremain = nil
		return
	}
	return c.Conn.Write(bufs...)
}

func (c *RemainConn) GetCfg() *Config {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetCfg()
	}
	return nil
}
func (c *RemainConn) SetDst(dst Addr) {
	if cm := getConnMeta(c.Conn); cm != nil {
		cm.SetDst(dst)
	}
}
func (c *RemainConn) GetDst() Addr {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetDst()
	}
	return nil
}
func (c *RemainConn) GetHost() string {
	if cm := getConnMeta(c.Conn); cm != nil {
		return cm.GetHost()
	}
	return ""
}

type SimpleHTTPConn struct {
	Conn
	host string
	req  bool
	resp bool
	// parserMu guards the parser field against Close, which runs on the
	// opposite Pipe direction while Read is consuming the response header.
	// The parser buffer is deliberately heap-allocated instead of taken from
	// the shared pool: Close can then only drop the reference, never return
	// the buffer for reuse while Read may still be parsing into it.
	parserMu sync.Mutex
	parser   *utils.HTTPHeaderParser
	// remain holds payload bytes that arrived with the response header.
	// Only the Read direction touches it, so it needs no lock; keeping it
	// here (instead of wrapping Conn in a RemainConn) avoids racing the
	// Conn interface field with concurrent Writes.
	remain []byte
}

func (conn *SimpleHTTPConn) Close() error {
	// Close the underlying conn first so a Read blocked on it wakes up
	err := conn.Conn.Close()
	conn.parserMu.Lock()
	// Drop the reference only: the buffer is heap-allocated, so a Read that
	// already captured the parser keeps using it safely until it returns.
	conn.parser = nil
	conn.parserMu.Unlock()
	return err
}

func (conn *SimpleHTTPConn) Write(bufs ...[]byte) (n int, err error) {
	for _, b := range bufs {
		n += len(b)
	}
	if len(bufs) == 0 {
		return conn.Conn.Write()
	}
	b := flatten(bufs)
	if !conn.req {
		return conn.Conn.Write(b)
	}
	req := buildSimpleObfsRequest(conn.host, n)
	conn.host = ""
	conn.req = false
	return conn.Conn.Write(utils.StringToSlice(req), b)
}

func (conn *SimpleHTTPConn) Read(buf []byte, pool *utils.BufPool) (segs [][]byte, err error) {
	if len(conn.remain) > 0 {
		n := copy(buf, conn.remain)
		conn.remain = conn.remain[n:]
		if len(conn.remain) == 0 {
			conn.remain = nil
		}
		return [][]byte{buf[:n]}, nil
	}
	if !conn.resp {
		return conn.Conn.Read(buf, pool)
	}
	conn.parserMu.Lock()
	if conn.parser == nil {
		conn.parser = utils.NewHTTPHeaderParser(make([]byte, buffersize))
	}
	parser := conn.parser
	conn.parserMu.Unlock()
	var rdbuf []byte
	if len(buf) < buffersize {
		if pool != nil {
			rdbuf = pool.Get(buffersize)
		} else {
			rdbuf = utils.GetBuf(buffersize)
			defer utils.PutBuf(rdbuf)
		}
	} else {
		rdbuf = buf
	}
	off := 0
	for {
		// Guard against a response header that fills the buffer without a
		// terminator: past this point the inner read gets an empty slice,
		// returns (0, nil) without any syscall, and the loop would spin
		// forever with deadlines never consulted.
		if off >= len(rdbuf) {
			err = fmt.Errorf("http obfs response header too large from %s", conn.RemoteAddr().String())
			return
		}
		var nm int
		nsegs, rerr := conn.Conn.Read(rdbuf[off:], pool)
		if rerr != nil {
			err = rerr
			return
		}
		for _, s := range nsegs {
			nm += len(s)
		}
		var ok bool
		ok, err = parser.Read(rdbuf[off : off+nm])
		if err != nil {
			return
		}
		off += nm
		if ok {
			hdrlen := parser.HeaderLen()
			n := copy(buf, rdbuf[hdrlen:off])
			if hdrlen+n < off {
				remain := make([]byte, off-hdrlen-n)
				copy(remain, rdbuf[hdrlen+n:off])
				conn.remain = remain
			}
			conn.parserMu.Lock()
			// Identity check: Close may have already dropped this parser;
			// only clear our own reference. The buffer is heap-allocated,
			// so there is no pool ownership to hand back.
			if conn.parser == parser {
				conn.parser = nil
			}
			conn.parserMu.Unlock()
			conn.resp = false
			return [][]byte{buf[:n]}, nil
		}
	}
}

// prefixConn replays bytes that were already consumed from the underlying
// connection before continuing to read from it. Used by the TLS obfs accept
// path, where the ClientHello and subsequent TLS records can arrive in one
// TCP segment and must still pass through the record layer.
type prefixConn struct {
	Conn
	prefix []byte
}

func (c *prefixConn) Read(buf []byte, pool *utils.BufPool) ([][]byte, error) {
	if len(c.prefix) > 0 {
		p := c.prefix
		c.prefix = nil
		// len, not cap: a caller with spare capacity but a short len would
		// otherwise truncate the replayed bytes and lose them.
		if len(buf) >= len(p) {
			n := copy(buf, p)
			return [][]byte{buf[:n]}, nil
		}
		return [][]byte{p}, nil
	}
	return c.Conn.Read(buf, pool)
}

func (c *prefixConn) Unwrap() Conn { return c.Conn }

type SimpleTLSConn struct {
	Conn
	sessionID []byte
	frameLen  int
	clireq    bool
	cliresp   bool
	srvresp   bool
	host      string
	wlock     sync.Mutex
	rr        io.Reader // persistent reader for inner conn (with buffering)
}

func (conn *SimpleTLSConn) initReader() {
	if conn.rr == nil {
		conn.rr = AsReader(conn.Conn, nil)
	}
}

func (conn *SimpleTLSConn) readExact(n int, dst []byte) error {
	conn.initReader()
	_, err := io.ReadFull(conn.rr, dst)
	return err
}

func (conn *SimpleTLSConn) cliHandshake() (err error) {
	conn.initReader()
	frame := make([]byte, 5)
	for it := 0; it < 2; it++ {
		_, err = io.ReadFull(conn.rr, frame)
		if err != nil {
			return
		}
		frameLen := int(binary.BigEndian.Uint16(frame[3:5]))
		data := make([]byte, frameLen)
		_, err = io.ReadFull(conn.rr, data)
		if err != nil {
			return
		}
	}
	return
}

func (conn *SimpleTLSConn) Read(buf []byte, pool *utils.BufPool) (segs [][]byte, err error) {
	conn.initReader()
	if conn.cliresp {
		conn.cliresp = false
		if err = conn.cliHandshake(); err != nil {
			return
		}
	}
	if conn.frameLen == 0 {
		frameBuf := make([]byte, 5)
		_, err = io.ReadFull(conn.rr, frameBuf)
		if err != nil {
			return
		}
		conn.frameLen = int(binary.BigEndian.Uint16(frameBuf[3:]))
	}
	if len(buf) > conn.frameLen {
		buf = buf[:conn.frameLen]
	}
	n, err := io.ReadFull(conn.rr, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		return
	}
	conn.frameLen -= n
	return [][]byte{buf[:n]}, nil
}

// maxSimpleTLSTicketLen caps the payload bundled into the ClientHello's
// session ticket. The server's handshake sniffing rejects ClientHello
// records above 16389 bytes outright, so the bundled part must stay well
// below that after adding the hello/record overhead (≈450 bytes + host).
const maxSimpleTLSTicketLen = 14000

func (conn *SimpleTLSConn) writeBuffersInLock(data []byte) (n int, err error) {
	n = len(data)
	if n == 0 {
		return
	}
	if conn.srvresp {
		// The ServerHello's third record carries the payload in a 16-bit
		// length field. Keep the bundled part within one record and emit
		// any remainder as regular application-data records; the peer's
		// record layer consumes lengths only, so the split is transparent.
		bundled := n
		if bundled > 65535 {
			bundled = 65535
		}
		merged := make([]byte, 512+bundled)
		tlsLen := utils.GenTLSServerHello(merged, bundled, conn.sessionID)
		copy(merged[tlsLen:], data[:bundled])
		merged = merged[:tlsLen+bundled]
		conn.srvresp = false
		if _, err = conn.Conn.Write(merged); err != nil {
			n = 0
			return
		}
		if bundled < n {
			if _, err = conn.writeChunksInLock(data[bundled:]); err != nil {
				n = 0
			}
		}
		return
	}
	if conn.clireq {
		// Same 16-bit limit inside the session ticket, plus the server-side
		// ClientHello record cap (see maxSimpleTLSTicketLen); the rest goes
		// out as application-data records after the handshake record.
		bundled := n
		if bundled > maxSimpleTLSTicketLen {
			bundled = maxSimpleTLSTicketLen
		}
		merged := make([]byte, 512+32+bundled)
		tlsLen := utils.GenTLSClientHello(merged, conn.host, utils.GetRandomBytes(32), data[:bundled])
		merged = merged[:tlsLen]
		conn.clireq = false
		conn.host = ""
		if _, err = conn.Conn.Write(merged); err != nil {
			n = 0
			return
		}
		if bundled < n {
			if _, err = conn.writeChunksInLock(data[bundled:]); err != nil {
				n = 0
			}
		}
		return
	}
	if n > 65535 {
		_, err = conn.writeChunksInLock(data)
		if err != nil {
			n = 0
		}
		return
	}
	merged := make([]byte, 5+n)
	merged[0] = 0x17
	merged[1] = 0x03
	merged[2] = 0x03
	binary.BigEndian.PutUint16(merged[3:5], uint16(n))
	copy(merged[5:], data)
	_, err = conn.Conn.Write(merged)
	if err != nil {
		n = 0
	}
	return
}

// writeChunksInLock emits data as 0x17 application-data records of at most
// 65535 bytes each. Caller must hold wlock.
func (conn *SimpleTLSConn) writeChunksInLock(data []byte) (n int, err error) {
	for off := 0; off < len(data); {
		chunk := len(data) - off
		if chunk > 65535 {
			chunk = 65535
		}
		frame := make([]byte, 5+chunk)
		frame[0] = 0x17
		frame[1] = 0x03
		frame[2] = 0x03
		binary.BigEndian.PutUint16(frame[3:5], uint16(chunk))
		copy(frame[5:], data[off:off+chunk])
		if _, err = conn.Conn.Write(frame); err != nil {
			return off, err
		}
		off += chunk
	}
	return len(data), nil
}

func (conn *SimpleTLSConn) Write(bufs ...[]byte) (n int, err error) {
	conn.wlock.Lock()
	defer conn.wlock.Unlock()
	for _, b := range bufs {
		n += len(b)
	}
	if n == 0 {
		return 0, nil
	}
	_, err = conn.writeBuffersInLock(flatten(bufs))
	return
}

func (conn *SimpleTLSConn) Unwrap() Conn { return conn.Conn }
func (conn *SimpleTLSConn) GetCfg() *Config {
	if cm := getConnMeta(conn.Conn); cm != nil {
		return cm.GetCfg()
	}
	return nil
}
func (conn *SimpleTLSConn) SetDst(dst Addr) {
	if cm := getConnMeta(conn.Conn); cm != nil {
		cm.SetDst(dst)
	}
}
func (conn *SimpleTLSConn) GetDst() Addr {
	if cm := getConnMeta(conn.Conn); cm != nil {
		return cm.GetDst()
	}
	return nil
}
func (conn *SimpleTLSConn) GetHost() string {
	if cm := getConnMeta(conn.Conn); cm != nil {
		return cm.GetHost()
	}
	return ""
}

func DialObfs(target string, c *Config) (conn Conn, err error) {
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()

	if c.ObfsMethod == "wstunnel" {
		var host string
		if len(c.ObfsHost) > 0 {
			host = c.ObfsHost[rand.IntN(len(c.ObfsHost))]
		}
		return DialWsConn(target, host, c)
	}

	var tconn *BaseConn
	tconn, err = DialTCP(target, c)
	if tconn != nil {
		conn = tconn
	}
	if err != nil {
		return
	}
	var host string
	if len(c.ObfsHost) == 0 {
		host = defaultObfsHost
	} else if len(c.ObfsHost) == 1 {
		host = c.ObfsHost[0]
	} else {
		host = c.ObfsHost[rand.IntN(len(c.ObfsHost))]
	}
	if c.ObfsMethod == "websocket" {
		conn = &SimpleHTTPConn{
			Conn: conn,
			host: host,
			req:  true,
			resp: true,
		}
		return
	}
	if c.ObfsMethod == "tls" {
		conn = &SimpleTLSConn{
			Conn:    conn,
			host:    host,
			clireq:  true,
			cliresp: true,
		}
		return
	}
	req := buildHTTPRequest(fmt.Sprintf("Host: %s\r\nX-Online-Host: %s\r\n", host, host))
	obfsconn, ok := conn.(*ObfsConn)
	if !ok {
		obfsconn = NewObfsConn(conn)
	}
	obfsconn.wremain = []byte(req)
	obfsconn.resp = true
	conn = obfsconn
	return
}

func obfsAcceptHandler(conn Conn, lis *listener) (result AcceptResult) {
	defer func() {
		if conn != nil && result.Action != AcceptContinue {
			conn.Close()
		}
	}()
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err := ReadN(conn, buf, nil)
	if err != nil || n == 0 {
		return
	}
	var remain, wremain []byte
	remain = DupBuffer(buf[:n])
	if n > 4 && string(buf[:4]) != "POST" {
		if string(buf[:4]) == "GET " {
			parser := utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
			defer utils.PutBuf(parser.GetBuf())
			// A websocket handshake split across TCP segments must be fed
			// incrementally; rejecting at the first partial read broke the
			// upgrade and stranded the connection in the SS parser.
			n2 := n
			fed := 0
			upgraded := false
			for {
				ok, perr := parser.Read(buf[fed:n2])
				if perr != nil {
					break
				}
				fed = n2
				if ok {
					uv, uok := parser.Load([]byte("Upgrade"))
					if uok && len(uv) > 0 && bytes.Equal(uv[0], []byte("websocket")) {
						cv, cok := parser.Load([]byte("Connection"))
						if cok && len(cv) > 0 && bytes.Equal(cv[0], []byte("Upgrade")) {
							remain = DupBuffer(buf[parser.HeaderLen():n2])
							wremain = []byte(buildSimpleObfsResponse())
							upgraded = true
						}
					}
					break
				}
				if n2 >= len(buf) {
					break
				}
				nn, rerr := ReadN(conn, buf[n2:], nil)
				if rerr != nil || nn == 0 {
					break
				}
				n2 += nn
			}
			if !upgraded && n2 > n {
				remain = DupBuffer(buf[:n2])
			}
		} else if buf[0] == 0x16 && n > 0x20 {
			tlsVer := binary.BigEndian.Uint16(buf[1:3])
			tlsLen := int(binary.BigEndian.Uint16(buf[3:5])) + 5
			if tlsVer > tls.VersionTLS12 || tlsVer < 0x0300 {
				goto OUT
			}
			if tlsLen > n {
				if tlsLen > 16389 {
					goto OUT
				}
				newBuf := utils.GetBuf(tlsLen)
				defer utils.PutBuf(newBuf)
				_, err = io.ReadFull(AsReader(conn, nil), newBuf[n:tlsLen])
				if err != nil {
					return
				}
				copy(newBuf, buf[:n])
				buf = newBuf
				n = tlsLen
			}
			ok, nh, cliMsg := utils.ParseTLSClientHelloMsg(buf[:n])
			if ok && cliMsg != nil {
				inner := conn
				if len(buf[nh:n]) > 0 {
					// The client's ClientHello and following TLS records
					// coalesced into one TCP segment. These bytes are
					// already record-framed: replay them through the record
					// layer below SimpleTLSConn instead of bypassing it.
					inner = &prefixConn{Conn: conn, prefix: DupBuffer(buf[nh:n])}
				}
				conn = &SimpleTLSConn{Conn: inner, sessionID: DupBuffer(cliMsg.SessionId), srvresp: true}
				if len(cliMsg.SessionTicket) > 0 {
					conn = &RemainConn{Conn: conn, remain: DupBuffer(cliMsg.SessionTicket)}
				}
				result = AcceptResult{AcceptContinue, conn}
				return
			}
		}
	OUT:
		result = AcceptResult{AcceptContinue, &RemainConn{Conn: conn, remain: remain, wremain: wremain}}
		return
	}
	resp := buildHTTPResponse("")
	obfsconn := NewObfsConn(conn)
	obfsconn.remain = remain
	obfsconn.wremain = []byte(resp)
	obfsconn.req = true
	result = AcceptResult{AcceptContinue, obfsconn}
	return
}

type wsConn struct {
	*websocket.Conn
	buf          []byte
	bufCh        chan []byte
	errCh        chan error
	readDeadline time.Time
	closeCh      chan struct{}
	closeOnce    sync.Once
}

func newWsConn(conn *websocket.Conn) *wsConn {
	wsconn := &wsConn{
		Conn:    conn,
		bufCh:   make(chan []byte, 16),
		errCh:   make(chan error, 1),
		closeCh: make(chan struct{}),
	}
	go wsconn.readLoop()
	return wsconn
}

func (c *wsConn) readLoop() {
	var t int
	var msg []byte
	var err error
	defer func() {
		if err != nil {
			c.errCh <- err
		}
		c.closeOnce.Do(func() {
			close(c.closeCh)
		})
	}()

	for {
		t, msg, err = c.Conn.ReadMessage()
		if err != nil {
			break
		} else if t != websocket.BinaryMessage {
			err = fmt.Errorf("unexpected websocket message type %v", t)
			break
		}

		select {
		case c.bufCh <- msg:
		case <-c.closeCh:
			return
		}
	}
}

// Read reads data from the connection. It blocks until there is at least one byte of data available, or an error occurs.
func (c *wsConn) Read(b []byte) (n int, err error) {
	if len(c.buf) > 0 {
		n = copy(b, c.buf)
		c.buf = c.buf[n:]
		if len(c.buf) == 0 {
			c.buf = nil
		}
		return
	}

	var timerCh <-chan time.Time

	if !c.readDeadline.IsZero() {
		now := time.Now()
		if now.After(c.readDeadline) {
			err = os.ErrDeadlineExceeded
			return
		}

		t := time.NewTimer(c.readDeadline.Sub(now))
		defer t.Stop()

		timerCh = t.C
	}

	// drainBuffered returns one queued message if any is pending; the
	// readLoop may have exited while messages were still queued, and those
	// bytes are valid data the caller should see before the error/EOF.
	drainBuffered := func() (int, bool) {
		select {
		case buf := <-c.bufCh:
			n = copy(b, buf)
			buf = buf[n:]
			if len(buf) > 0 {
				c.buf = buf
			}
			return n, true
		default:
			return 0, false
		}
	}

	if n, got := drainBuffered(); got {
		return n, nil
	}

	select {
	case err = <-c.errCh:
		// The blocking select may pick the error even when a message landed
		// in the queue concurrently; prefer still-readable data.
		if n, got := drainBuffered(); got {
			err = nil
			return n, err
		}
		return

	case <-timerCh:
		err = os.ErrDeadlineExceeded
		return

	case buf := <-c.bufCh:
		n = copy(b, buf)
		buf = buf[n:]
		if len(buf) > 0 {
			c.buf = buf
		}
		return

	case <-c.closeCh:
		// readLoop exited through its closeCh path without posting to
		// errCh (local Close). Without this case a deadline-less Read
		// would block forever.
		if n, got := drainBuffered(); got {
			err = nil
			return n, err
		}
		err = io.EOF
		return
	}
}

func (c *wsConn) Write(b []byte) (n int, err error) {
	err = c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err == nil {
		n = len(b)
	}
	return
}

func (c *wsConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closeCh)
	})
	err := c.Conn.Close()
	return err
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *wsConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.Conn.SetWriteDeadline(t)
}

func DialWsConn(address, host string, cfg *cfg) (Conn, error) {
	// Bound the HTTP upgrade exchange (and, with it, the underlying TCP dial
	// when ipselect is off): a backend that accepts TCP but never answers the
	// upgrade would otherwise pin a handler goroutine and connection forever.
	var p *dialPolicy
	if cfg != nil {
		p = cfg.dialPolicy()
	}
	hsTimeout := 30 * time.Second
	if p != nil && p.timeout > 0 {
		hsTimeout = time.Duration(p.timeout) * time.Second
	}
	d := websocket.Dialer{
		ReadBufferSize:   10240,
		WriteBufferSize:  10240,
		Subprotocols:     []string{"0.0.1"},
		HandshakeTimeout: hsTimeout,
	}

	// Route the underlying TCP dial through ipselect so dual-stack proxy
	// addresses get raced/scored too.
	var mode string
	if p != nil {
		mode = normalizeIPSelectMode(p.ipSelect)
	}
	if mode != ipSelectOff {
		policy := newIPSelPolicy(cfg)
		useScore := mode == ipSelectSmart
		var cache *ipScoreCache
		if useScore {
			cache = cfg.getIPSelectCache()
		}
		d.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialIPSelect(ctx, network, addr, policy, cache, useScore)
		}
	}

	reqHeader := make(http.Header)

	if len(host) > 0 {
		reqHeader.Add("Host", host)
	}

	if !strings.HasPrefix(address, "ws://") && !strings.HasPrefix(address, "wss://") {
		address = "ws://" + address
	}

	conn, _, err := d.Dial(address, reqHeader)
	if err != nil {
		return nil, err
	}

	return newBaseConn(newWsConn(conn), cfg), nil
}
