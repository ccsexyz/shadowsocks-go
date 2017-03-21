package shadowsocks

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	delayConnTick = time.Millisecond * 10
)

type DelayConn struct {
	net.Conn
	wbuf      [buffersize]byte
	off       int
	cond      *sync.Cond
	die       chan bool
	started   bool
	destroyed bool
}

func (c *DelayConn) Close() error {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()
	if c.destroyed {
		return nil
	}
	c.destroyed = true
	close(c.die)
	c.cond.Broadcast()
	return c.Conn.Close()
}

func (c *DelayConn) sendLoopOnce() (ok bool) {
	c.cond.L.Lock()
	var err error
	defer func() {
		c.cond.L.Unlock()
		if err != nil {
			c.Close()
		}
	}()
	if c.destroyed {
		return
	}
	if c.off == 0 {
		c.cond.Wait()
	}
	if c.destroyed {
		return
	}
	if c.off == 0 {
		return true
	}
	c.cond.L.Unlock()
	timer := time.NewTimer(delayConnTick)
	select {
	case <-c.die:
		c.cond.L.Lock()
		return
	case <-timer.C:
	}
	c.cond.L.Lock()
	if c.off == 0 {
		return true
	}
	_, err = c.Conn.Write(c.wbuf[:c.off])
	c.off = 0
	return err == nil
}

func (c *DelayConn) sendLoop() {
	for {
		if !c.sendLoopOnce() {
			break
		}
	}
}

func (c *DelayConn) Write(b []byte) (n int, err error) {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()
	n = len(b)
	defer func() {
		if err != nil {
			n = 0
		}
	}()
	if n == 0 {
		return
	}
	if n+c.off >= buffersize {
		buf := make([]byte, n+c.off)
		copy(buf, c.wbuf[:c.off])
		copy(buf[c.off:], b)
		_, err = c.Conn.Write(buf)
		c.off = 0
		return
	}
	copy(c.wbuf[c.off:], b)
	c.off += len(b)
	if !c.started {
		c.started = true
		go c.sendLoop()
	}
	c.cond.Signal()
	return
}

func delayAcceptHandler(conn net.Conn, _ *listener) net.Conn {
	return &DelayConn{
		Conn: conn,
		die:  make(chan bool),
		cond: sync.NewCond(&sync.Mutex{}),
	}
}

type ObfsConn struct {
	net.Conn
	//rbuf   [buffersize]byte
	remain   []byte
	chunkLen int
}

func (c *ObfsConn) Write(b []byte) (n int, err error) {
	n = len(b)
	if n == 0 {
		return
	}
	defer func() {
		if err != nil {
			n = 0
		}
	}()
	wbuf := make([]byte, n+16)
	length := copy(wbuf, []byte(fmt.Sprintf("%x\r\n", n)))
	copy(wbuf[length:], b)
	length += n
	wbuf[length] = '\r'
	wbuf[length+1] = '\n'
	_, err = c.Conn.Write(wbuf[:length+2])
	return
}

func (c *ObfsConn) doRead(b []byte) (n int, err error) {
	if len(c.remain) == 0 {
		n, err = c.Conn.Read(b)
	} else {
		n = copy(b, c.remain)
		if n == len(c.remain) {
			c.remain = nil
		} else {
			c.remain = c.remain[n:]
		}
	}
	return
}

func (c *ObfsConn) Read(b []byte) (n int, err error) {
	if len(b) == 0 {
		return
	}
	if c.chunkLen <= 2 && c.chunkLen > 0 {
		_, err = c.doRead(b[:c.chunkLen])
		if err != nil {
			return
		}
		c.chunkLen = 0
	}
	if c.chunkLen == 0 {
		var chunkLenStr string
		for {
			n, err = c.doRead(b[:1])
			if err != nil {
				return
			}
			if n == 0 {
				err = fmt.Errorf("short read")
				return
			}
			c := b[0]
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
				chunkLenStr += string(c)
				continue
			}
			if c == '\r' {
				continue
			}
			if c == '\n' {
				break
			}
		}
		if len(chunkLenStr) == 0 {
			err = fmt.Errorf("incorrect chunked data")
			return
		}
		var i int64
		i, err = strconv.ParseInt(chunkLenStr, 16, 0)
		if err != nil {
			return
		}
		c.chunkLen = int(i) + 2
	}
	var buf []byte
	if c.chunkLen > len(b) {
		buf = b
	} else {
		buf = b[:c.chunkLen]
	}
	n, err = c.doRead(buf)
	if err != nil {
		return
	}
	c.chunkLen -= n
	if c.chunkLen < 2 {
		n -= 2 - c.chunkLen
	}
	return
}

func NewObfsConn(conn net.Conn) *ObfsConn {
	return &ObfsConn{
		Conn: conn,
	}
}

type RemainConn struct {
	net.Conn
	remain []byte
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

func DialObfs(target string, c *Config) (conn net.Conn, err error) {
	conn, err = net.Dial("tcp", target)
	if err != nil {
		return
	}
	var host string
	if len(c.ObfsHost) == 0 {
		host = defaultObfsHost
	} else if len(c.ObfsHost) == 1 {
		host = c.ObfsHost[0]
	} else {
		host = c.ObfsHost[int(src.Int63()%int64(len(c.ObfsHost)))]
	}
	req := buildHTTPRequest(fmt.Sprintf("Host: %s\r\nX-Online-Host: %s\r\n", host, host))
	_, err = io.WriteString(conn, req)
	if err != nil {
		return
	}
	buf := make([]byte, buffersize)
	parser := newHTTPReplyParser()
	var flag bool
	var n int
	for !flag {
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			err = fmt.Errorf("short read from %v", conn)
			return
		}
		it := 0
		ok := false
		for ; it < n && !ok && err == nil; it++ {
			ok, err = parser.read(buf[it])
		}
		if err != nil {
			return
		}
		if ok {
			obfsconn := NewObfsConn(conn)
			remain := buf[it:n]
			if len(remain) != 0 {
				obfsconn.remain = make([]byte, len(remain))
				copy(obfsconn.remain, remain)
			}
			conn = obfsconn
			return
		}
	}
	return
}

func obfsAcceptHandler(conn net.Conn, lis *listener) (c net.Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	buf := make([]byte, buffersize)
	parser := newHTTPRequestParser()
	var n int
	var err error
	for {
		n, err = conn.Read(buf)
		if err != nil || n == 0 {
			return
		}
		if n > 4 && string(buf[:4]) != "POST" {
			c = &RemainConn{
				Conn:   conn,
				remain: buf[:n],
			}
			return
		}
		it := 0
		ok := false
		for ; it < n && !ok && err == nil; it++ {
			ok, err = parser.read(buf[it])
		}
		if err != nil {
			return
		}
		if !ok {
			continue
		}
		rep := buildHTTPResponse("")
		_, err = io.WriteString(conn, rep)
		if err != nil {
			return
		}
		obfsconn := NewObfsConn(conn)
		remain := buf[it:n]
		if len(remain) != 0 {
			obfsconn.remain = make([]byte, len(remain))
			copy(obfsconn.remain, remain)
		}
		c = obfsconn
		return
	}
}
