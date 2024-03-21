package ss

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
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
	pool     *ConnPool
	eos      bool // end of stream
	lock     sync.Mutex
	rlock    sync.Mutex
	wlock    sync.Mutex
	destroy  bool
	status   int
}

func (c *ObfsConn) Close() (err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.rlock.Lock()
	defer c.rlock.Unlock()
	if c.destroy {
		return
	}
	c.destroy = true
	if c.pool == nil || c.req || c.resp {
		err = c.RemainConn.Close()
		return
	}
	c.wlock.Lock()
	defer c.wlock.Unlock()
	_, err = c.writeBuffers([][]byte{nil})
	if err != nil {
		err = c.RemainConn.Close()
		return
	}
	c.SetReadDeadline(time.Now())
	c.rlock.Lock()
	c.SetReadDeadline(time.Time{})
	defer c.rlock.Unlock()
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	for !c.eos {
		_, err = c.readInLock(buf)
		if err != nil {
			if c.eos {
				break
			} else {
				err = c.RemainConn.Close()
				return
			}
		}
	}
	err = c.pool.Put(&ObfsConn{
		RemainConn: c.RemainConn,
		pool:       c.pool,
	})
	if err != nil {
		err = c.RemainConn.Close()
	}
	return
}

func (c *ObfsConn) writeBuffers(bufs [][]byte) (n int, err error) {
	wbufs := make([][]byte, 0, 3+len(bufs))
	length := 0
	for _, buf := range bufs {
		length += len(buf)
	}
	wbufs = append(wbufs, []byte(fmt.Sprintf("%x\r\n", length)))
	wbufs = append(wbufs, bufs...)
	wbufs = append(wbufs, []byte("\r\n"))
	return c.RemainConn.WriteBuffers(wbufs)
}

func (c *ObfsConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return c.RemainConn.Write(b)
	}
	c.wlock.Lock()
	defer c.wlock.Unlock()
	if c.destroy {
		err = fmt.Errorf("write to closed connection")
		return
	}
	n, err = c.writeBuffers([][]byte{b})
	return
}

func (c *ObfsConn) WriteBuffers(b [][]byte) (n int, err error) {
	c.wlock.Lock()
	defer c.wlock.Unlock()
	if c.destroy {
		err = fmt.Errorf("write to closed connection")
		return
	}
	n, err = c.writeBuffers(b)
	return
}

func (c *ObfsConn) readObfsHeader(b []byte) (n int, err error) {
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err = c.RemainConn.Read(buf)
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
	return c.RemainConn.Read(b)
}

func (c *ObfsConn) readInLock(b []byte) (n int, err error) {
	if len(b) == 0 {
		return c.RemainConn.Read(b)
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

func (c *ObfsConn) Read(b []byte) (n int, err error) {
	c.rlock.Lock()
	defer c.rlock.Unlock()
	if c.destroy {
		err = fmt.Errorf("read from closed connection")
		return
	}
	n, err = c.readInLock(b)
	return
}

func NewObfsConn(conn Conn) *ObfsConn {
	return &ObfsConn{RemainConn: RemainConn{Conn: conn}}
}

type RemainConn struct {
	Conn
	remain  []byte
	wremain []byte
}

func DecayRemainConn(conn Conn) Conn {
	rconn, ok := conn.(*RemainConn)
	if ok && len(rconn.remain) == 0 && len(rconn.wremain) == 0 {
		return rconn.Conn
	}
	return conn
}

func (c *RemainConn) Read(b []byte) (n int, err error) {
	if len(c.remain) == 0 {
		return c.Conn.Read(b)
	}
	n = copy(b, c.remain)
	if n == len(c.remain) {
		c.remain = nil
	} else {
		c.remain = c.remain[n:]
	}
	return
}

func (c *RemainConn) Write(b []byte) (n int, err error) {
	if len(c.wremain) != 0 {
		_, err = c.Conn.WriteBuffers([][]byte{c.wremain, b})
		if err != nil {
			return
		}
		c.wremain = nil
		n = len(b)
		return
	}
	return c.Conn.Write(b)
}

func (c *RemainConn) WriteBuffers(b [][]byte) (n int, err error) {
	if len(c.wremain) != 0 {
		bufs := make([][]byte, 0, len(b)+1)
		bufs = append(bufs, c.wremain)
		bufs = append(bufs, b...)
		_, err = c.Conn.WriteBuffers(bufs)
		if err != nil {
			return
		}
		c.wremain = nil
		for _, v := range b {
			n += len(v)
		}
		return
	}
	return c.Conn.WriteBuffers(b)
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

func (conn *SimpleHTTPConn) Write(b []byte) (n int, err error) {
	return conn.WriteBuffers([][]byte{b})
}

func (conn *SimpleHTTPConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	if !conn.req {
		return conn.Conn.WriteBuffers(bufs)
	}
	for _, buf := range bufs {
		n += len(buf)
	}
	req := buildSimpleObfsRequest(conn.host, n)
	newbufs := make([][]byte, len(bufs)+1)
	newbufs[0] = utils.StringToSlice(req)
	copy(newbufs[1:], bufs)
	n, err = conn.Conn.WriteBuffers(newbufs)
	conn.host = ""
	conn.req = false
	return
}

func (conn *SimpleHTTPConn) Read(b []byte) (n int, err error) {
	if !conn.resp {
		return conn.Conn.Read(b)
	}
	if conn.parser == nil {
		conn.parser = utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
	}
	var buf []byte
	if len(b) < buffersize {
		buf = utils.GetBuf(buffersize)
		defer utils.PutBuf(buf)
	} else {
		buf = b
	}
	off := 0
	for {
		var nm int
		nm, err = conn.Conn.Read(buf[off:])
		if err != nil {
			return
		}
		var ok bool
		ok, err = conn.parser.Read(buf[off : off+nm])
		if err != nil {
			return
		}
		off += nm
		if ok {
			hdrlen := conn.parser.HeaderLen()
			n = copy(b, buf[hdrlen:off])
			if hdrlen+n < off {
				conn.Conn = &RemainConn{Conn: conn.Conn, remain: DupBuffer(buf[hdrlen+n : off])}
			}
			utils.PutBuf(conn.parser.GetBuf())
			conn.parser = nil
			conn.resp = false
			return
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
}

func (conn *SimpleTLSConn) cliHandshake(b []byte) (err error) {
	var buf []byte
	if len(b) < buffersize {
		buf = utils.GetBuf(buffersize)
		defer utils.PutBuf(buf)
	} else {
		buf = b
	}
	for it := 0; it < 2; it++ {
		_, err = io.ReadFull(conn.Conn, buf[:5])
		if err != nil {
			return
		}
		frameLen := int(binary.BigEndian.Uint16(buf[3:5]))
		_, err = io.ReadFull(conn.Conn, buf[:frameLen])
		if err != nil {
			return
		}
	}
	return
}

func (conn *SimpleTLSConn) Read(b []byte) (n int, err error) {
	if conn.cliresp {
		conn.cliresp = false
		err = conn.cliHandshake(b)
		if err != nil {
			return
		}
	}
	for conn.frameLen == 0 {
		frameBuf := make([]byte, 5)
		_, err = io.ReadFull(conn.Conn, frameBuf)
		if err != nil {
			return
		}
		conn.frameLen = int(binary.BigEndian.Uint16(frameBuf[3:]))
	}
	if len(b) > conn.frameLen {
		b = b[:conn.frameLen]
	}
	n, err = conn.Conn.Read(b)
	if n > 0 {
		conn.frameLen -= n
	}
	return
}

func (conn *SimpleTLSConn) writeBuffersInLock(bufs [][]byte) (n int, err error) {
	if len(bufs) == 0 {
		return
	}
	buflen := len(bufs[0])
	for _, buf := range bufs[1:] {
		buflen += len(buf)
	}
	var wbufs [][]byte
	if conn.srvresp {
		tlsBuf := utils.GetBuf(buflen + 512)
		defer utils.PutBuf(tlsBuf)
		tlsLen := utils.GenTLSServerHello(tlsBuf, buflen, conn.sessionID)
		wbufs = append(wbufs, tlsBuf[:tlsLen])
		wbufs = append(wbufs, bufs...)
		conn.srvresp = false
	} else if conn.clireq {
		tlsBuf := utils.GetBuf(buflen + 512)
		defer utils.PutBuf(tlsBuf)
		buf := utils.GetBuf(buflen)
		defer utils.PutBuf(buf)
		for _, v := range bufs {
			n += copy(buf[n:], v)
		}
		tlsLen := utils.GenTLSClientHello(tlsBuf, conn.host, utils.GetRandomBytes(32), buf[:buflen])
		wbufs = append(wbufs, tlsBuf[:tlsLen])
		conn.clireq = false
		conn.host = ""
	} else {
		frameBuf := utils.GetBuf(5)
		defer utils.PutBuf(frameBuf)
		copy(frameBuf, []byte{0x17, 0x03, 0x03})
		binary.BigEndian.PutUint16(frameBuf[3:], uint16(buflen))
		wbufs = append(wbufs, frameBuf[:5])
		wbufs = append(wbufs, bufs...)
	}
	_, err = conn.Conn.WriteBuffers(wbufs)
	if err != nil {
		n = 0
	}
	n = buflen
	return
}

func (conn *SimpleTLSConn) Write(b []byte) (n int, err error) {
	conn.wlock.Lock()
	defer conn.wlock.Unlock()
	return conn.writeBuffersInLock([][]byte{b})
}

func (conn *SimpleTLSConn) WriteBuffers(b [][]byte) (n int, err error) {
	conn.wlock.Lock()
	defer conn.wlock.Unlock()
	return conn.writeBuffersInLock(b)
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
			host = c.ObfsHost[rand.Intn(len(c.ObfsHost))]
		}
		return DialWsConn(target, host, c)
	}

	if c.pool != nil {
		conn, err = c.pool.GetNonblock()
	}
	if err != nil || c.pool == nil {
		var tconn *TCPConn
		tconn, err = DialTCP(target, c)
		if tconn != nil {
			conn = tconn
		}
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
		host = c.ObfsHost[rand.Intn(len(c.ObfsHost))]
	}
	_, port, err := net.SplitHostPort(c.Remoteaddr)
	if err != nil {
		return
	}
	if c.ObfsMethod == "websocket" {
		if port != "80" {
			host = host + port
		}
		conn = &SimpleHTTPConn{
			Conn: conn,
			host: host,
			req:  true,
			resp: true,
		}
		return
	}
	if c.ObfsMethod == "tls" {
		if port != "443" {
			host = host + port
		}
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
		obfsconn.pool = c.pool
	}
	obfsconn.wremain = []byte(req)
	obfsconn.resp = true
	conn = obfsconn
	return
}

func obfsAcceptHandler(conn Conn, lis *listener) (c Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	buf := utils.GetBuf(buffersize)
	defer utils.PutBuf(buf)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	var remain, wremain []byte
	remain = DupBuffer(buf[:n])
	if n > 4 && string(buf[:4]) != "POST" {
		if string(buf[:4]) == "GET " {
			for {
				parser := utils.NewHTTPHeaderParser(utils.GetBuf(buffersize))
				defer utils.PutBuf(parser.GetBuf())
				ok, err := parser.Read(buf[:n])
				if err != nil || ok == false {
					break
				}
				uv, ok := parser.Load([]byte("Upgrade"))
				if ok == false || len(uv) == 0 || !bytes.Equal(uv[0], []byte("websocket")) {
					break
				}
				cv, ok := parser.Load([]byte("Connection"))
				if ok == false || len(cv) == 0 || !bytes.Equal(cv[0], []byte("Upgrade")) {
					break
				}
				remain = DupBuffer(buf[parser.HeaderLen():n])
				wremain = []byte(buildSimpleObfsResponse())
				break
			}
		} else if buf[0] == 0x16 && n > 0x20 {
			tlsVer := binary.BigEndian.Uint16(buf[1:3])
			tlsLen := int(binary.BigEndian.Uint16(buf[3:5])) + 5
			if tlsVer > tls.VersionTLS12 || tlsVer < tls.VersionSSL30 {
				goto OUT
			}
			if tlsLen > n {
				if tlsLen > 16389 {
					goto OUT
				}
				newBuf := utils.GetBuf(tlsLen)
				defer utils.PutBuf(newBuf)
				_, err = io.ReadFull(conn, newBuf[n:tlsLen])
				if err != nil {
					return
				}
				copy(newBuf, buf[:n])
				buf = newBuf
				n = tlsLen
			}
			ok, nh, cliMsg := utils.ParseTLSClientHelloMsg(buf[:n])
			if ok && cliMsg != nil {
				if len(buf[nh:n]) > 0 {
					conn = &RemainConn{Conn: conn, remain: DupBuffer(buf[nh:n])}
				}
				conn = &SimpleTLSConn{Conn: conn, sessionID: DupBuffer(cliMsg.SessionId), srvresp: true}
				if len(cliMsg.SessionTicket) > 0 {
					conn = &RemainConn{Conn: conn, remain: DupBuffer(cliMsg.SessionTicket)}
				}
				c = conn
				return
			}
			//log.Println(buf[:n], n, ok, cliMsg)
		}
	OUT:
		c = &RemainConn{Conn: conn, remain: remain, wremain: wremain}
		return
	}
	resp := buildHTTPResponse("")
	obfsconn := NewObfsConn(conn)
	obfsconn.remain = remain
	obfsconn.wremain = []byte(resp)
	obfsconn.req = true
	obfsconn.pool = lis.c.pool
	c = obfsconn
	return
}

type wsConn struct {
	*websocket.Conn
	buf []byte
	rem []byte
}

func (c *wsConn) Read(b []byte) (n int, err error) {
	if len(c.rem) > 0 {
		n = copy(b, c.rem)
		c.rem = c.rem[n:]
		if len(c.rem) == 0 {
			utils.PutBuf(c.buf)
			c.buf = nil
			c.rem = nil
		}
		return
	}

	t, msg, err := c.Conn.ReadMessage()
	if err != nil {
		return
	} else if t != websocket.BinaryMessage {
		err = fmt.Errorf("unexpected websocket message type %v", t)
		return
	}

	n = copy(b, msg)
	if n < len(msg) {
		c.buf = utils.CopyBuffer(msg[n:])
		c.rem = c.buf
	}
	return
}

func (c *wsConn) Write(b []byte) (n int, err error) {
	err = c.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err == nil {
		n = len(b)
	}
	return
}

func (c *wsConn) WriteBuffers(bufs [][]byte) (n int, err error) {
	var b []byte

	nbufs := len(bufs)
	if nbufs > 1 {
		b = utils.CopyBuffers(bufs)
		defer utils.PutBuf(b)
	} else if nbufs == 1 {
		b = bufs[0]
	}

	return c.Write(b)
}

func (c *wsConn) Close() error {
	err := c.Conn.Close()
	if c.buf != nil {
		utils.PutBuf(c.buf)
		c.buf = nil
	}
	return err
}

func (c *wsConn) SetDeadline(t time.Time) error {
	err := c.Conn.SetReadDeadline(t)
	if err == nil {
		err = c.Conn.SetWriteDeadline(t)
	}
	return err
}

func DialWsConn(address, host string, cfg *cfg) (Conn, error) {
	d := websocket.Dialer{
		ReadBufferSize:  10240,
		WriteBufferSize: 10240,
		Subprotocols:    []string{"0.0.1"},
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

	return newTCPConn(&wsConn{Conn: conn}, cfg), nil
}
