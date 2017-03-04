package main

import (
	"io"
	"log"
	"math/rand"
	"net"
	"time"
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
	info *ssinfo
	xu1s bool
}

func (c *Conn) Close() error {
	if c.xu1s {
		c.wbuf = nil
		c.rbuf = nil
		select {
		case <-xudie:
			c.xu1s = false
		case xuch <- c.Conn:
			return nil
		}
	}
	return c.Conn.Close()
}

func NewConn(conn net.Conn, info *ssinfo) *Conn {
	return &Conn{
		Conn: conn,
		info: info,
		rbuf: make([]byte, buffersize),
		wbuf: make([]byte, buffersize),
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		_, err = io.ReadFull(c.Conn, c.rbuf[:c.info.ivlen])
		if err != nil {
			return
		}
		c.dec, err = NewDecrypter(c.info.method, c.info.password, c.rbuf[:c.info.ivlen])
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
		c.enc, err = NewEncrypter(c.info.method, c.info.password)
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
			log.Println("续了", a, "秒")
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
