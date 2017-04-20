package shadowsocks

import (
	"fmt"
	"io"
	"math/rand"
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
	wbuf    [buffersize]byte
	off     int
	lock    sync.Mutex
	destroy bool
	timer   *time.Timer
}

func (c *DelayConn) Close() (err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.destroy = true
	err = c.Conn.Close()
	return
}

func (c *DelayConn) Write(b []byte) (n int, err error) {
	l := len(b)
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.destroy {
		err = fmt.Errorf("use of closed connection")
		return
	}
	if l+c.off >= buffersize {
		if c.off != 0 {
			buf := make([]byte, l+c.off)
			copy(buf, c.wbuf[:c.off])
			copy(buf[c.off:], b)
			b = buf
		}
		_, err = c.Conn.Write(b)
		c.off = 0
		if err == nil {
			n = l
		}
		if c.timer != nil {
			c.timer.Stop()
			c.timer = nil
		}
		return
	}
	copy(c.wbuf[c.off:], b)
	c.off += l
	n = l
	if c.timer == nil {
		c.timer = time.AfterFunc(delayConnTick, func() {
			c.lock.Lock()
			defer c.lock.Unlock()
			c.timer = nil
			if c.off == 0 {
				return
			}
			if c.destroy {
				return
			}
			_, err := c.Conn.Write(c.wbuf[:c.off])
			c.off = 0
			if err != nil {
				c.Close()
			}
		})
	}
	return
}

func NewDelayConn(conn net.Conn) *DelayConn {
	return &DelayConn{
		Conn: conn,
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
	pool     *ConnPool
	eos      bool // end of stream
	lock     sync.Mutex
	rlock    sync.Mutex
	wlock    sync.Mutex
	destroy  bool
}

func (c *ObfsConn) Close() (err error) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.destroy {
		return
	}
	c.destroy = true
	if c.pool == nil {
		err = c.RemainConn.Close()
		return
	}
	c.wlock.Lock()
	defer c.wlock.Unlock()
	_, err = c.write(nil)
	if err != nil {
		err = c.RemainConn.Close()
		return
	}
	c.SetReadDeadline(time.Now())
	c.rlock.Lock()
	c.SetReadDeadline(time.Time{})
	defer c.rlock.Unlock()
	buf := make([]byte, buffersize)
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

func (c *ObfsConn) write(b []byte) (n int, err error) {
	n = len(b)
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
	n, err = c.write(b)
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

func (c *ObfsConn) readInLock(b []byte) (n int, err error) {
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
	if c.chunkLen == 2 {
		buf := make([]byte, 2)
		_, err = io.ReadFull(&(c.RemainConn), buf)
		if err == nil {
			n = 0
			c.eos = true
			err = fmt.Errorf("read from closed obfsconn")
		}
		return
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
	if c.pool != nil {
		conn, err = c.pool.GetNonblock()
	}
	if err != nil || c.pool == nil {
		conn, err = net.Dial("tcp", target)
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
	obfsconn.pool = lis.c.pool
	c = obfsconn
	return
}
