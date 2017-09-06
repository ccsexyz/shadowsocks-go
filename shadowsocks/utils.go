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

	"github.com/ccsexyz/utils"
)

const (
	defaultMethod       = "aes-256-cfb"
	defaultPassword     = "secret"
	defaultTimeout      = 65
	buffersize          = 4096
	verSocks4Resp       = 0
	verSocks4           = 4
	verSocks5           = 5
	cmdConnect          = 1
	cmdUDP              = 3
	cmdSocks4OK         = 0x5A
	typeIPv4            = 1
	typeDm              = 3
	typeIPv6            = 4
	typeMux             = 0x6D
	typeTs              = 0x74 // timestamp
	typeNop             = 0x90 // [nop 1 byte] [noplen 1 byte (< 128)] [zero data, noplen byte]
	typePartEnc         = 0x37 // [partEnc 1 byte] [partLen 1 byte] [partLen * 1024 bytes data]
	lenIPv4             = 4
	lenIPv6             = 16
	lenTs               = 8
	ivmapHighWaterLevel = 100000
	ivmapLowWaterLevel  = 10000
	muxaddr             = "mux:12580"
	muxhost             = "mux"
	muxport             = 12580
	defaultObfsHost     = "www.bing.com"
)

var (
	bufPool *sync.Pool
)

func init() {
	bufPool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, buffersize)
		},
	}
}

type cb func()

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

func ParseAddrWithMultipleBackends(b, buf []byte, configs []*Config) (addr SockAddr, data []byte, dec utils.Decrypter, chs *Config, err error) {
	addr, data, dec, chs, _, err = ParseAddrWithMultipleBackendsAndPartEncLen(b, buf, configs)
	return
}

func ParseAddrWithMultipleBackendsAndPartEncLen(b, buf []byte, configs []*Config) (addr SockAddr, data []byte, dec utils.Decrypter, chs *Config, partEncLen int, err error) {
	defer func() {
		if chs != nil {
			err = nil
			data = DupBuffer(data)
			addr = SockAddr(DupBuffer([]byte(addr)))
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
		dec, err = utils.NewDecrypter(config.Method, config.Password, b[:config.Ivlen])
		if err != nil {
			continue
		}
		dec.Decrypt(buf, b[config.Ivlen:config.Ivlen+1])
		off := config.Ivlen + 1
		nop := false
		atyp := buf[0]
	lo:
		for {
			switch atyp {
			default:
				break lo
			case typeNop:
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
			case typeTs:
				if n < off+lenTs+1 {
					continue outer
				}
				dec.Decrypt(buf, b[off:off+lenTs])
				ts := binary.BigEndian.Uint64(buf[:lenTs])
				if !checkTimestamp(int64(ts)) {
					continue outer
				}
				off += lenTs
				dec.Decrypt(buf, b[off:off+1])
				atyp = buf[0]
				off++
			case typePartEnc:
				if n < off+2 {
					continue outer
				}
				dec.Decrypt(buf, b[off:off+2])
				partEncLen = int(buf[0]) * 1024
				atyp = buf[1]
				buf[0] = buf[1]
				off += 2
			}
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
		dec, err = utils.NewDecrypter(chs.Method, chs.Password, b[:chs.Ivlen])
		if err != nil {
			return
		}
		dec.Decrypt(buf, b[chs.Ivlen:])
		addr, data, partEncLen, err = ParseAddrAndPartEncLen(buf)
	}
	return
}

func checkTimestamp(ts int64) (ok bool) {
	nts := time.Now().Unix()
	if nts >= ts {
		return (nts - ts) <= 64
	}
	return (ts - nts) <= 64
}

func ParseAddr(b []byte) (addr SockAddr, data []byte, err error) {
	addr, data, _, err = ParseAddrAndPartEncLen(b)
	return
}

func ParseAddrAndPartEncLen(b []byte) (addr SockAddr, data []byte, partEncLen int, err error) {
	err = errInvalidHeader
	n := len(b)
	if n < 1 {
		return
	}
	var nop bool
	atyp := b[0]
l:
	for {
		switch atyp {
		default:
			break l
		case typeNop:
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
		case typeTs:
			if n < lenTs+1+1 {
				return
			}
			ts := binary.BigEndian.Uint64(b[1 : 1+lenTs])
			if !checkTimestamp(int64(ts)) {
				return
			}
			b = b[lenTs+1:]
			n = len(b)
			atyp = b[0]
		case typePartEnc:
			if n < 3 {
				return
			}
			partEncLen = int(b[1]) * 1024
			b = b[2:]
			n = len(b)
			atyp = b[0]
		}
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
	addr = SockAddr(DupBuffer(header))
	data = DupBuffer(data)
	err = nil
	return
}

func DupBuffer(b []byte) (b2 []byte) {
	l := len(b)
	if l != 0 {
		b2 = make([]byte, l)
		copy(b2, b)
	}
	return
}

func Pipe(c1, c2 net.Conn, c *Config) {
	defer c1.Close()
	defer c2.Close()
	c1die := make(chan bool)
	c2die := make(chan bool)
	updated := true
	f := func(dst, src net.Conn, die chan bool, buf []byte) {
		defer close(die)
		defer bufPool.Put(buf)
		var n int
		var err error
		for err == nil {
			n, err = src.Read(buf)
			// log.Println(n, err, src.LocalAddr(), src.RemoteAddr())
			if n > 0 || err == nil {
				updated = true
				_, err = dst.Write(buf[:n])
				updated = true
			}
		}
	}
	buf1 := bufPool.Get().([]byte)
	buf2 := bufPool.Get().([]byte)
	go f(c1, c2, c1die, buf1)
	go f(c2, c1, c2die, buf2)
	if c != nil && c.Timeout > 0 {
		ticker := time.NewTicker(time.Duration(c.Timeout) * time.Second)
		for {
			select {
			case <-ticker.C:
				if updated {
					updated = false
					continue
				}
			case <-c1die:
			case <-c2die:
			}
			return
		}
	} else {
		select {
		case <-c1die:
		case <-c2die:
		}
		return
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
			err = fmt.Errorf("unexpected conn with type %T", conn)
		}
	}()
	switch i := conn.(type) {
	case *sconn:
		c = i.Conn
	case *SsConn:
		c = i.Conn
	case *DebugConn:
		c = i.Conn
	case *DstConn:
		c = i.Conn
	case *RemainConn:
		c = i.Conn
	case *LimitConn:
		c = i.Conn
	case *MuxConn:
		c = i.conn
	}
	return
}

func GetTCPConn(conn net.Conn) (c *net.TCPConn, err error) {
	c, ok := conn.(*net.TCPConn)
	if !ok {
		conn, err = GetInnerConn(conn)
		if err != nil {
			return
		}
		c, err = GetTCPConn(conn)
	}
	return
}

func GetSsConn(conn net.Conn) (c *SsConn, err error) {
	c, ok := conn.(*SsConn)
	if !ok {
		conn, err = GetInnerConn(conn)
		if err != nil {
			return
		}
		c, err = GetSsConn(conn)
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

func GetRemainConn(conn net.Conn) (r *RemainConn, err error) {
	r, ok := conn.(*RemainConn)
	if !ok {
		conn, err = GetInnerConn(conn)
		if err != nil {
			return
		}
		r, err = GetRemainConn(conn)
	}
	return
}

func GetConn(conn net.Conn) (c Conn) {
	var ok bool
	c, ok = conn.(Conn)
	if !ok {
		c = Newsconn(conn)
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

func Dial(network, address string) (Conn, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return Newsconn(conn), err
}

type Dialer interface {
	Dial(string, *Config) (Conn, error)
}
