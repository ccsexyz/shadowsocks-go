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

type ObfsConn struct {
	RemainConn
	resp     bool
	req      bool
	chunkLen int
	eos      bool // end of stream
	lock     sync.Mutex
	rlock    sync.Mutex
	wlock    sync.Mutex
	destroy  bool
	status   int
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

	c.wlock.Lock()
	_, err = c.writeChunked(nil)
	if err != nil {
		c.wlock.Unlock()
		return c.RemainConn.Close()
	}
	c.wlock.Unlock()

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
	ok, err := parser.Read(buf[:n])
	if err != nil {
		return
	}
	if !ok {
		err = fmt.Errorf("unexpected obfs header from %s", c.RemoteAddr().String())
		return
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
					c.chunkLen *= 16
					c.chunkLen += int(b2[0] - '0')
					b2 = b2[1:]
				} else if b2[0] >= 'a' && b2[0] <= 'f' {
					c.chunkLen *= 16
					c.chunkLen += 10 + int(b2[0]-'a')
					b2 = b2[1:]
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
	host   string
	req    bool
	resp   bool
	parser *utils.HTTPHeaderParser
}

func (conn *SimpleHTTPConn) Close() error {
	if conn.parser != nil {
		utils.PutBuf(conn.parser.GetBuf())
		conn.parser = nil
	}
	return conn.Conn.Close()
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
	if !conn.resp {
		return conn.Conn.Read(buf, pool)
	}
	if conn.parser == nil {
		conn.parser = utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
	}
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
		ok, err = conn.parser.Read(rdbuf[off : off+nm])
		if err != nil {
			return
		}
		off += nm
		if ok {
			hdrlen := conn.parser.HeaderLen()
			n := copy(buf, rdbuf[hdrlen:off])
			if hdrlen+n < off {
				remain := make([]byte, off-hdrlen-n)
				copy(remain, rdbuf[hdrlen+n:off])
				conn.Conn = &RemainConn{Conn: conn.Conn, remain: remain}
			}
			utils.PutBuf(conn.parser.GetBuf())
			conn.parser = nil
			conn.resp = false
			return [][]byte{buf[:n]}, nil
		}
	}
}

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

func (conn *SimpleTLSConn) writeBuffersInLock(data []byte) (n int, err error) {
	n = len(data)
	if n == 0 {
		return
	}
	var merged []byte
	if conn.srvresp {
		merged = make([]byte, 512+n)
		tlsLen := utils.GenTLSServerHello(merged, n, conn.sessionID)
		copy(merged[tlsLen:], data)
		merged = merged[:tlsLen+n]
		conn.srvresp = false
	} else if conn.clireq {
		merged = make([]byte, 512+32+n)
		tlsLen := utils.GenTLSClientHello(merged, conn.host, utils.GetRandomBytes(32), data)
		merged = merged[:tlsLen]
		conn.clireq = false
		conn.host = ""
	} else if n > 65535 {
		for off := 0; off < n; {
			chunk := n - off
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
				n = 0
				return
			}
			off += chunk
		}
		return
	} else {
		merged = make([]byte, 5+n)
		merged[0] = 0x17
		merged[1] = 0x03
		merged[2] = 0x03
		binary.BigEndian.PutUint16(merged[3:5], uint16(n))
		copy(merged[5:], data)
	}
	_, err = conn.Conn.Write(merged)
	if err != nil {
		n = 0
	}
	return
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
			ok, err := parser.Read(buf[:n])
			if err == nil && ok {
				uv, ok := parser.Load([]byte("Upgrade"))
				if ok && len(uv) > 0 && bytes.Equal(uv[0], []byte("websocket")) {
					cv, ok := parser.Load([]byte("Connection"))
					if ok && len(cv) > 0 && bytes.Equal(cv[0], []byte("Upgrade")) {
						remain = DupBuffer(buf[parser.HeaderLen():n])
						wremain = []byte(buildSimpleObfsResponse())
					}
				}
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
				conn = &SimpleTLSConn{Conn: conn, sessionID: DupBuffer(cliMsg.SessionId), srvresp: true}
				if len(buf[nh:n]) > 0 {
					conn = &RemainConn{Conn: conn, remain: DupBuffer(buf[nh:n])}
				}
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

	select {
	case err = <-c.errCh:
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
	d := websocket.Dialer{
		ReadBufferSize:  10240,
		WriteBufferSize: 10240,
		Subprotocols:    []string{"0.0.1"},
	}

	// Route the underlying TCP dial through ipselect so dual-stack proxy
	// addresses get raced/scored too.
	mode := normalizeIPSelectMode(cfg.IPSelect)
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
