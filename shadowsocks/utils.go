package shadowsocks

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	defaultMethod       = "aes-256-cfb"
	defaultPassword     = "you should have a password"
	buffersize          = 4096
	typeIPv4            = 1
	typeDm              = 3
	typeIPv6            = 4
	typeNop             = 0x90 // [nop 1 byte] [noplen 1 byte (< 128)] [random data noplen byte]
	lenIPv4             = 4
	lenIPv6             = 16
	ivmapHighWaterLevel = 100000
	ivmapLowWaterLevel  = 10000
	Udprelayaddr        = "UdpRelayOverTcp:65535"
	defaultObfsHost     = "www.bing.com"
)

func PutRandomBytes(b []byte) {
	binary.Read(rand.Reader, binary.BigEndian, b)
}

func GetRandomBytes(len int) []byte {
	if len <= 0 {
		return nil
	}
	data := make([]byte, len)
	PutRandomBytes(data)
	return data
}

func PutHeader(b []byte, host string, port int) (n int) {
	n = len(host)
	b[0] = typeDm
	b[1] = byte(n)
	copy(b[2:], []byte(host))
	binary.BigEndian.PutUint16(b[2+n:], uint16(port))
	n += 4
	return
}

func GetHeader(host string, port int) (buf []byte, err error) {
	hostlen := len(host)
	if hostlen > 255 {
		err = fmt.Errorf("host length can't be greater than 255")
		return
	}
	buf = make([]byte, hostlen+4)
	PutHeader(buf, host, port)
	return
}

func ParseAddrWithMultipleBackends(b []byte, configs []*Config) (host string, port int, data []byte, dec Decrypter, chs *Config) {
	n := len(b)
	if n < 1 {
		return
	}
	type candidate struct {
		atyp byte
		nop  bool
		off  int
		dec  Decrypter
		c    *Config
		host string
		port int
	}
	var candidates []*candidate
	buf := make([]byte, n)
	for _, config := range configs {
		if n < config.Ivlen {
			continue
		}
		d, err := NewDecrypter(config.Method, config.Password, b[:config.Ivlen])
		if err != nil {
			continue
		}
		cand := candidate{off: config.Ivlen, dec: d}
		d.Decrypt(buf, b[config.Ivlen:config.Ivlen+1])
		atyp := buf[0]
		ok := true
	outer:
		for atyp == typeNop {
			d.Decrypt(buf, b[cand.off+1:cand.off+2])
			noplen := int(buf[0])
			if noplen >= 128 || n < cand.off+noplen+2+1 {
				ok = false
				break outer
			}
			d.Decrypt(buf, b[cand.off+2:cand.off+2+noplen])
			for _, v := range buf[:cand.off] {
				if v != 0 {
					ok = false
					break outer
				}
			}
			cand.off += 2 + noplen
			cand.nop = true
			d.Decrypt(buf, b[cand.off:cand.off+1])
			atyp = buf[0]
		}
		if !ok {
			continue
		}
		cand.off++
		switch atyp {
		default:
			continue
		case typeDm:
			if cand.off >= n {
				continue
			}
			d.Decrypt(buf[:1], b[cand.off:cand.off+1])
			cand.off++
			dmlen := int(buf[0])
			if n-cand.off < dmlen+2 {
				continue
			}
			d.Decrypt(buf[:dmlen], b[cand.off:cand.off+dmlen])
			for _, v := range buf[:dmlen] {
				if !((v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') || (v >= '0' && v <= '9') || v == '.' || v == '-' || v == '_') {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			cand.off += dmlen
			host = string(buf[:dmlen])
			d.Decrypt(buf[:2], b[cand.off:cand.off+2])
			cand.off += 2
			port = int(binary.BigEndian.Uint16(buf))
			if n > cand.off {
				n -= cand.off
				copy(buf, b[cand.off:])
				d.Decrypt(b, buf[:n])
				data = b[:n]
			}
			dec = d
			chs = config
			return
		case typeIPv6:
			if cand.nop || n < cand.off+lenIPv6+2 {
				continue
			}
			d.Decrypt(buf[:lenIPv6+2], b[cand.off:cand.off+lenIPv6+2])
			cand.host = net.IP(buf[:lenIPv6]).String()
			cand.port = int(binary.BigEndian.Uint16(buf[lenIPv6:]))
			cand.off += lenIPv6 + 2
		case typeIPv4:
			if cand.nop || n < cand.off+lenIPv4+2 {
				continue
			}
			d.Decrypt(buf[:lenIPv4+2], b[cand.off:cand.off+lenIPv4+2])
			cand.host = net.IP(buf[:lenIPv4]).String()
			cand.port = int(binary.BigEndian.Uint16(buf[lenIPv4:]))
			cand.off += lenIPv4 + 2
		}
		if cand.port == 80 || cand.port == 443 || cand.port == 22 || cand.port == 53 {
			host = cand.host
			port = cand.port
			dec = d
			chs = config
			n -= cand.off
			copy(buf, b[cand.off:])
			d.Decrypt(b, buf[:n])
			data = b[:n]
			return
		}
		cand.c = config
		candidates = append(candidates, &cand)
	}
	if len(candidates) != 0 {
		cand := candidates[0]
		host = cand.host
		port = cand.port
		dec = cand.dec
		chs = cand.c
		n -= cand.off
		copy(buf, b[cand.off:])
		cand.dec.Decrypt(b, buf[:n])
		data = b[:n]
	}
	return
}

func ParseAddr(b []byte) (host string, port int, data []byte) {
	n := len(b)
	if n < 1 {
		return
	}
	atyp := b[0]
	var nop bool
	for atyp == typeNop {
		noplen := int(b[1])
		if noplen >= 128 || n < noplen+2+1 {
			return
		}
		for _, v := range b[2 : noplen+2] {
			if v != 0 {
				return
			}
		}
		b = b[noplen+2:]
		n = len(b)
		atyp = b[0]
		nop = true
	}
	switch atyp {
	default:
		return
	case typeIPv4:
		if nop || n < lenIPv4+2+1 {
			return
		}
		data = b[lenIPv4+2+1:]
		host = net.IP(b[1 : lenIPv4+1]).String()
		port = int(binary.BigEndian.Uint16(b[lenIPv4+1:]))
	case typeIPv6:
		if nop || n < lenIPv6+2+1 {
			return
		}
		data = b[lenIPv6+2+1:]
		host = net.IP(b[1 : 1+lenIPv6]).String()
		port = int(binary.BigEndian.Uint16(b[lenIPv6+1:]))
	case typeDm:
		dmlen := int(b[1])
		if n < dmlen+1+2+1 {
			return
		}
		data = b[dmlen+1+2+1:]
		for _, v := range b[2 : 2+dmlen] {
			if !((v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') || (v >= '0' && v <= '9') || v == '.' || v == '-' || v == '_') {
				return
			}
		}
		host = string(b[2 : 2+dmlen])
		port = int(binary.BigEndian.Uint16(b[dmlen+2:]))
	}
	return
}

func Pipe(c1, c2 net.Conn) {
	c1die := make(chan bool)
	c2die := make(chan bool)
	f := func(dst, src net.Conn, die chan bool, buf []byte) {
		defer close(die)
		var n int
		var err error
		for err == nil {
			n, err = src.Read(buf)
			if n > 0 || err == nil {
				_, err = dst.Write(buf[:n])
			}
		}
	}
	go f(c1, c2, c1die, make([]byte, buffersize))
	go f(c2, c1, c2die, make([]byte, buffersize))
	select {
	case <-c1die:
	case <-c2die:
	}
}

type Limiter struct {
	limit      int
	nbytes     int
	last       int64
	totalBytes int64
	lock       sync.Mutex
}

func NewLimiter(limit int) *Limiter {
	return &Limiter{limit: limit, last: time.Now().UnixNano(), nbytes: limit}
}

func (l *Limiter) Update(nbytes int) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.totalBytes += int64(nbytes)
	if l.limit == 0 {
		return
	}
	ns := time.Now().UnixNano()
	if l.last == 0 {
		l.last = ns
		l.nbytes = l.limit
	}
	l.nbytes -= nbytes
	for l.nbytes <= 0 {
		nextNs := l.last + int64(1000000000)
		if nextNs > ns {
			time.Sleep(time.Nanosecond * time.Duration(nextNs-ns))
		}
		l.last = ns
		l.nbytes += l.limit
	}
}

func (l *Limiter) GetLimit() int {
	return l.limit
}

func (l *Limiter) SetLimit(limit int) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.limit = limit
}

func (l *Limiter) GetTotalBytes() int64 {
	return l.totalBytes
}

func GetInnerConn(conn net.Conn) (c net.Conn, err error) {
	defer func() {
		if c == nil {
			err = fmt.Errorf("unexpected conn")
		}
	}()
	switch i := conn.(type) {
	case *Conn:
		c = i.Conn
	case *Conn2:
		c = i.Conn
	case *DebugConn:
		c = i.Conn
	case *DstConn:
		c = i.Conn
	case *RemainConn:
		c = i.Conn
	case *DelayConn:
		c = i.Conn
	case *LimitConn:
		c = i.Conn
	}
	return
}

func GetConn(conn net.Conn) (c *Conn, err error) {
	c, ok := conn.(*Conn)
	if !ok {
		conn, err = GetInnerConn(conn)
		if err != nil {
			return
		}
		c, err = GetConn(conn)
	}
	return
}

func GetDstConn(conn net.Conn) (dst *DstConn, err error) {
	dst, ok := conn.(*DstConn)
	if !ok {
		conn, err = GetInnerConn(conn)
		if err != nil {
			return
		}
		dst, err = GetDstConn(conn)
	}
	return
}

func GetLimitConn(conn net.Conn) (l *LimitConn, err error) {
	l, ok := conn.(*LimitConn)
	if !ok {
		conn, err = GetInnerConn(conn)
		if err != nil {
			return
		}
		l, err = GetLimitConn(conn)
	}
	return
}

// CheckConn Check the Conn whether is still alive
func CheckConn(conn net.Conn) bool {
	if conn != nil {
		if _, err := conn.Write([]byte{}); err == nil {
			return true
		}
	}
	return false
}
