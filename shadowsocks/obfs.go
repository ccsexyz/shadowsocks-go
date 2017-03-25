package shadowsocks

import (
	"fmt"
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
	select {
	case <-c.die:
		c.cond.L.Lock()
		return
	case <-time.After(delayConnTick):
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

func NewDelayConn(conn net.Conn) *DelayConn {
	return &DelayConn{
		Conn: conn,
		die:  make(chan bool),
		cond: sync.NewCond(&sync.Mutex{}),
	}
}

func delayAcceptHandler(conn net.Conn, _ *listener) net.Conn {
	return NewDelayConn(conn)
}

type ObfsConn struct {
	RemainConn
	resp     bool
	req      bool
	chunkLen int
}

func (c *ObfsConn) Write(b []byte) (n int, err error) {
	n = len(b)
	if n == 0 {
		return c.RemainConn.Write(b)
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
	_, err = c.RemainConn.Write(wbuf[:length+2])
	return
}

func (c *ObfsConn) readObfsHeader(b []byte) (n int, err error) {
	buf := make([]byte, buffersize)
	n, err = c.RemainConn.Read(buf)
	if err != nil {
		return
	}
	if n == 0 {
		err = fmt.Errorf("short read")
		return
	}
	ok := false
	it := 0
	if c.resp {
		parser := newHTTPReplyParser()
		for ; it < n && !ok && err == nil; it++ {
			ok, err = parser.read(buf[it])
		}
	} else if c.req {
		parser := newHTTPRequestParser()
		for ; it < n && !ok && err == nil; it++ {
			ok, err = parser.read(buf[it])
		}
	}
	if err != nil {
		return
	}
	if !ok {
		err = fmt.Errorf("unexpected obfs header from %s", c.RemoteAddr().String())
		return
	}
	c.resp = false
	c.req = false
	remain := buf[it:n]
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
			err = fmt.Errorf("unexcepted length character", string(c))
			return
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
	return &ObfsConn{RemainConn: RemainConn{Conn: conn}}
}

type RemainConn struct {
	net.Conn
	remain  []byte
	wremain []byte
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
		_, err = c.Conn.Write(append(c.wremain, b...))
		if err != nil {
			return
		}
		c.wremain = nil
		n = len(b)
		return
	}
	return c.Conn.Write(b)
}

func DialObfs(target string, c *Config) (conn net.Conn, err error) {
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
		}
	}()
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
	obfsconn := NewObfsConn(conn)
	obfsconn.wremain = []byte(req)
	obfsconn.resp = true
	conn = obfsconn
	return
}

func obfsAcceptHandler(conn net.Conn, lis *listener) (c net.Conn) {
	defer func() {
		if conn != nil && c == nil {
			conn.Close()
		}
	}()
	buf := make([]byte, buffersize)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return
	}
	if n > 4 && string(buf[:4]) != "POST" {
		c = &RemainConn{Conn: conn, remain: buf[:n]}
		return
	}
	resp := buildHTTPResponse("")
	obfsconn := NewObfsConn(conn)
	obfsconn.remain = buf[:n]
	obfsconn.wremain = []byte(resp)
	obfsconn.req = true
	c = obfsconn
	return
}

type LimitConn struct {
	net.Conn
	rlimit int
	rlast  int64
	rbytes int
	wlimit int
	wlast  int64
	wbytes int
}

func (c *LimitConn) Read(b []byte) (n int, err error) {
	if c.rlimit == 0 {
		return c.Conn.Read(b)
	}
	ns := time.Now().UnixNano()
	if c.rlast == 0 || c.rlast+int64(1000000000) < ns {
		c.rlast = ns
		c.rbytes = c.rlimit
	}
	if c.rbytes <= 0 {
		time.Sleep(time.Nanosecond * time.Duration(ns-c.rlast))
	}
	n, err = c.Conn.Read(b)
	c.rbytes -= n
	return
}

func (c *LimitConn) Write(b []byte) (n int, err error) {
	if c.wlimit == 0 {
		return c.Conn.Write(b)
	}
	ns := time.Now().UnixNano()
	if c.wlast == 0 || c.wlast+int64(1000000000) < ns {
		c.wlast = ns
		c.wbytes = c.wlimit
	}
	if c.wbytes <= 0 {
		time.Sleep(time.Nanosecond * time.Duration(ns-c.wlast))
	}
	n, err = c.Conn.Write(b)
	c.wbytes -= n
	return
}
