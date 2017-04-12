package shadowsocks

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

const (
	defaultMethod       = "aes-256-cfb"
	defaultPassword     = "you should have a password"
	buffersize          = 4096
	typeIPv4            = 1
	typeDm              = 3
	typeIPv6            = 4
	typeMux             = 0x6D
	typeNop             = 0x90 // [nop 1 byte] [noplen 1 byte (< 128)] [zero data, noplen byte]
	lenIPv4             = 4
	lenIPv6             = 16
	ivmapHighWaterLevel = 100000
	ivmapLowWaterLevel  = 10000
	muxaddr             = "mux:12580"
	muxhost             = "mux"
	muxport             = 12580
	Udprelayaddr        = "UdpRelayOverTcp:65535"
	defaultObfsHost     = "www.bing.com"
)

var (
	errInvalidHeader = fmt.Errorf("invalid header")
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

func ParseAddrWithMultipleBackends(b, buf []byte, configs []*Config) (addr SockAddr, data []byte, dec Decrypter, chs *Config, err error) {
	defer func() {
		if chs != nil {
			err = nil
		} else {
			if err == nil {
				err = errInvalidHeader
			}
			addr = nil
			data = nil
			dec = nil
		}
	}()
	n := len(b)
	if n < 1 {
		return
	}
	var candidates []*Config
outer:
	for _, config := range configs {
		if n < config.Ivlen+4 {
			continue
		}
		dec, err = NewDecrypter(config.Method, config.Password, b[:config.Ivlen])
		if err != nil {
			continue
		}
		dec.Decrypt(buf, b[config.Ivlen:config.Ivlen+1])
		off := config.Ivlen + 1
		nop := false
		atyp := buf[0]
		for atyp == typeNop {
			dec.Decrypt(buf, b[off:off+1])
			noplen := int(buf[0])
			if noplen >= 128 || n < off+noplen+1+1 {
				continue outer
			}
			off++
			dec.Decrypt(buf, b[off:off+noplen])
			for _, v := range buf[:noplen] {
				if v != 0 {
					continue outer
				}
			}
			off += noplen
			nop = true
			dec.Decrypt(buf, b[off:off+1])
			atyp = buf[0]
			off++
		}
		var port int
		switch atyp {
		default:
			continue
		case typeMux:
			if !nop {
				continue
			}
			chs = config
			dec.Decrypt(buf, b[off:])
			data = buf[:len(b)-off]
			addr = SockAddr([]byte{atyp})
			return
		case typeDm:
			if off+1 >= n {
				continue
			}
			dec.Decrypt(buf[1:2], b[off:off+1])
			off++
			dmlen := int(buf[1])
			if off+dmlen+2 > n {
				continue
			}
			dec.Decrypt(buf[2:2+dmlen+2], b[off:off+dmlen+2])
			for _, v := range buf[2 : 2+dmlen] {
				if !((v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') || (v >= '0' && v <= '9') || v == '.' || v == '-' || v == '_') {
					continue outer
				}
			}
			addr = SockAddr(buf[:2+dmlen+2])
			off += dmlen + 2
			if n > off {
				dec.Decrypt(buf[2+dmlen+2:], b[off:])
				data = buf[2+dmlen+2 : 2+dmlen+2+len(b[off:])]
			}
			chs = config
			return
		case typeIPv6:
			if nop || n < off+lenIPv6+2 {
				continue
			}
			dec.Decrypt(buf[1:lenIPv6+2+1], b[off:off+lenIPv6+2])
			off += lenIPv6 + 2
			port = int(binary.BigEndian.Uint16(buf[lenIPv6+1:]))
			addr = SockAddr(buf[:lenIPv6+2+1])
		case typeIPv4:
			if nop || n < off+lenIPv4+2 {
				continue
			}
			dec.Decrypt(buf[1:lenIPv4+2+1], b[off:off+lenIPv4+2])
			off += lenIPv4 + 2
			port = int(binary.BigEndian.Uint16(buf[lenIPv4+1:]))
			addr = SockAddr(buf[:lenIPv4+2+1])
		}
		if port == 80 || port == 443 || port == 22 || port == 53 || port == 8080 {
			dec.Decrypt(buf[off:], b[off:])
			data = buf[off:len(b)]
			chs = config
			return
		}
		candidates = append(candidates, config)
	}
	if len(candidates) != 0 {
		chs = candidates[0]
		dec, err = NewDecrypter(chs.Method, chs.Password, b[:chs.Ivlen])
		if err != nil {
			return
		}
		dec.Decrypt(buf, b[chs.Ivlen:])
		addr, data, err = ParseAddr(buf)
	}
	return
}

func ParseAddr(b []byte) (addr SockAddr, data []byte, err error) {
	err = errInvalidHeader
	n := len(b)
	if n < 1 {
		return
	}
	var nop bool
	atyp := b[0]
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
	var header []byte
	switch atyp {
	default:
		err = fmt.Errorf("unsupported atyp value %v", atyp)
		return
	case typeMux:
		if !nop {
			return
		}
		header = b[:1]
		data = b[1:]
	case typeIPv4:
		if nop || n < lenIPv4+2+1 {
			return
		}
		header = b[:lenIPv4+2+1]
		data = b[lenIPv4+2+1:]
	case typeIPv6:
		if nop || n < lenIPv6+2+1 {
			return
		}
		header = b[:lenIPv6+2+1]
		data = b[lenIPv6+2+1:]
	case typeDm:
		if n < 4 {
			return
		}
		dmlen := int(b[1])
		if n < dmlen+1+2+1 {
			return
		}
		for _, v := range b[2 : 2+dmlen] {
			if !((v >= 'A' && v <= 'Z') || (v >= 'a' && v <= 'z') || (v >= '0' && v <= '9') || v == '.' || v == '-' || v == '_') {
				return
			}
		}
		header = b[:2+dmlen+2]
		data = b[2+dmlen+2:]
	}
	addr = SockAddr(header)
	err = nil
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
	case *MuxConn:
		c = i.conn
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

type Addr interface {
	Host() string
	Port() string
	Header() []byte
}

type SockAddr []byte

func (b SockAddr) Host() string {
	switch b[0] {
	default:
		return SliceToString(b[2 : 2+int(b[1])])
	case typeIPv4:
		return net.IP(b[1 : lenIPv4+1]).String()
	case typeIPv6:
		return net.IP(b[1 : lenIPv6+1]).String()
	case typeMux:
		return muxhost
	}
}

func (b SockAddr) Port() string {
	var off int
	switch b[0] {
	default:
		off = int(b[1]) + 2
	case typeIPv4:
		off = lenIPv4 + 1
	case typeIPv6:
		off = lenIPv6 + 1
	case typeMux:
		return strconv.Itoa(muxport)
	}
	return strconv.Itoa(int(binary.BigEndian.Uint16(b[off:])))
}

func (b SockAddr) Header() []byte {
	return b
}

type DstAddr struct {
	host   string
	port   string
	header []byte
}

func (d *DstAddr) Host() string {
	return d.host
}

func (d *DstAddr) Port() string {
	return d.port
}

func (d *DstAddr) Header() []byte {
	if d.header == nil {
		port, _ := strconv.Atoi(d.port)
		d.header, _ = GetHeader(d.host, port)
	}
	return d.header
}

func SliceToString(b []byte) (s string) {
	pbytes := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	pstring := (*reflect.StringHeader)(unsafe.Pointer(&s))
	pstring.Data = pbytes.Data
	pstring.Len = pbytes.Len
	return
}

func StringToSlice(s string) (b []byte) {
	pbytes := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	pstring := (*reflect.StringHeader)(unsafe.Pointer(&s))
	pbytes.Data = pstring.Data
	pbytes.Len = pstring.Len
	pbytes.Cap = pstring.Len
	return
}

func SliceCopy(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}
