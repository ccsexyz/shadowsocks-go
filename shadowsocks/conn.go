package shadowsocks

import (
	"io"
	"log"
	"math/rand"
	"net"
	"time"
	"fmt"
)

var (
	xuch  chan net.Conn
	xudie chan bool
	src   = rand.NewSource(time.Now().UnixNano())
)

func init() {
	xuch = make(chan net.Conn, 32)
	xudie = make(chan bool)
	go xuroutine()
}

type Conn struct {
	net.Conn
	enc  Encrypter
	dec  Decrypter
	rbuf []byte
	wbuf []byte
	c    *Config
	xu1s bool
}

func (c *Conn) GetIV() (enciv []byte, deciv []byte) {
	if c.dec != nil {
		deciv = c.dec.GetIV()
	}
	if c.enc != nil {
		enciv = c.enc.GetIV()
	}
	return
}

func (c *Conn) Close() error {
	if c.xu1s {
		c.wbuf = nil
		c.rbuf = nil
		c.xu1s = false
		select {
		case <-xudie:
		case xuch <- c.Conn:
			return nil
		}
	}
	return c.Conn.Close()
}

func NewConn(conn net.Conn, c *Config) *Conn {
	return &Conn{
		Conn: conn,
		c:    c,
		rbuf: make([]byte, buffersize),
		wbuf: make([]byte, buffersize),
	}
}

func (c *Conn) Xu1s() {
	c.xu1s = true
}

func (c *Conn) Xu0s() {
	c.xu1s = false
}

func (c *Conn) Wbuf() []byte {
	return c.wbuf
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		_, err = io.ReadFull(c.Conn, c.rbuf[:c.c.Ivlen])
		if err != nil {
			return
		}
		if c.c.Type == "server" || c.c.Type == "ssproxy" {
			iv := string(c.rbuf[:c.c.Ivlen])
			c.c.IvMapLock.Lock()
			_, ok := c.c.IvMap[iv]
			if !ok {
				c.c.IvMap[iv] = true
			}
			c.c.IvMapLock.Unlock()
			if ok {
				err = fmt.Errorf("receive duplicate iv from %s, this means that you maight be attacked!", c.RemoteAddr().String())
				return
			}
		}
		c.dec, err = NewDecrypter(c.c.Method, c.c.Password, c.rbuf[:c.c.Ivlen])
		if err != nil {
			return
		}
	}
	rbuf := c.rbuf
	if len(c.rbuf) > len(b) {
		rbuf = rbuf[:len(b)]
	}
	n, err = c.Conn.Read(rbuf)
	if n > 0 {
		c.dec.Decrypt(b[:n], rbuf[:n])
	}
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.enc == nil {
		c.enc, err = NewEncrypter(c.c.Method, c.c.Password)
		if err != nil {
			return
		}
		iv := c.enc.GetIV()
		copy(c.wbuf, iv)
		n += len(iv)
	}
	var r []byte
	if len(b) > len(c.wbuf[n:]) {
		r = b[len(c.wbuf[n:]):]
		b = b[:len(c.wbuf[n:])]
	}
	c.enc.Encrypt(c.wbuf[n:], b)
	n, err = c.Conn.Write(c.wbuf[:n+len(b)])
	if err == nil && r != nil {
		var nbytes int
		nbytes, err = c.Write(r)
		n += nbytes
	}
	return
}

func xuroutine() {
	ticker := time.NewTicker(time.Second)
	mn := make(map[string]int)
	mc := make(map[string]net.Conn)
	defer func() {
		for _, v := range mc {
			v.Close()
		}
	}()
	for {
		select {
		case <-xudie:
			return
		case c := <-xuch:
			s := c.RemoteAddr().String()
			a := 0
			b := 0
			for b < 3 || b > 14 {
				b = int(src.Int63()%16 + 1)
				a += b
			}
			log.Println("you have xu ", a, "seconds")
			mn[s] = a
			mc[s] = c
		case <-ticker.C:
			for k, v := range mn {
				v--
				if v <= 0 {
					delete(mn, k)
					c, ok := mc[k]
					if ok {
						delete(mc, k)
						if _, ok := c.(*Conn); ok {
							c.(*Conn).xu1s = false
						}
						c.Close()
					}
				} else {
					mn[k] = v
				}
			}
		}
	}
}
