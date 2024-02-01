package ss

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
	"unicode"

	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

const (
	defaultMethod          = "aes-256-cfb"
	defaultPassword        = "secret"
	defaultTimeout         = 65
	buffersize             = 8192
	httpbuffersize         = 4096
	verSocks4Resp          = 0
	verSocks4              = 4
	verSocks5              = 5
	verSocks6              = 6
	cmdConnect             = 1
	cmdUDP                 = 3
	cmdSocks4OK            = 0x5A
	typeIPv4               = 1
	typeDm                 = 3
	typeIPv6               = 4
	typeMux                = 0x6D
	typeTs                 = 0x74 // timestamp
	typeNop                = 0x90 // [nop 1 byte] [noplen 1 byte (< 128)] [zero data, noplen byte]
	lenIPv4                = 4
	lenIPv6                = 16
	lenTs                  = 8
	muxaddr                = "mux:12580"
	muxhost                = "mux"
	muxport                = 12580
	defaultObfsHost        = "www.bing.com"
	defaultFilterCapacity  = 100000
	defaultFilterFalseRate = 0.00001
)

var (
	bufPool *sync.Pool
	nilConn = &TCPConn{}
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
	errInvalidHeader        = fmt.Errorf("invalid header")
	errDuplicatedInitVector = fmt.Errorf("receive duplicated iv")
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

type parseContext struct {
	data []byte
	addr *SockAddr
	dec  utils.CipherStream
	chs  *Config
}

func ParseAddrWithMultipleBackends(b []byte, configs []*Config) (*parseContext, error) {
	ctxs := make([]*parseContext, 0, len(configs))

	for _, cfg := range configs {
		dec, err := utils.NewDecrypter(cfg.Method, cfg.Password)
		if err != nil {
			continue
		}

		_, err = dec.Write(b)
		if err != nil {
			continue
		}

		buf, err := io.ReadAll(dec)
		if err != nil {
			continue
		}

		addr, data, err := ParseAddr(buf)
		if err != nil {
			continue
		}

		ctx := new(parseContext)
		ctx.data = data
		ctx.addr = addr
		ctx.dec = dec
		ctx.chs = cfg

		port := addr.PortNum()
		if port == 80 || port == 443 || port == 22 || port == 53 || port == 8080 {
			return ctx, nil
		}

		ctxs = append(ctxs, ctx)
	}

	if len(ctxs) == 0 {
		return nil, errInvalidHeader
	}

	return ctxs[0], nil
}

func checkTimestamp(ts int64) (ok bool) {
	nts := time.Now().Unix()
	if nts >= ts {
		return (nts - ts) <= 4
	}
	return (ts - nts) <= 4
}

// isAllowedInHost returns true if b is allowed in host.
// Host = IP | Domain
// IP = ipv4 | ipv6
func isAllowedInHost(b byte) bool {
	return unicode.IsLetter(rune(b)) || unicode.IsDigit(rune(b)) || b == '.' || b == '-' || b == '_' || b == ':' || b == '[' || b == ']'
}

func ParseAddr(b []byte) (addr *SockAddr, data []byte, err error) {
	err = errInvalidHeader
	addr = &SockAddr{}
	defer func() {
		if err != nil {
			addr = nil
		}
	}()
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
			addr.nop = nop
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
			addr.ts = true
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
			if !isAllowedInHost(v) {
				return
			}
		}
		header = b[:2+dmlen+2]
		data = b[2+dmlen+2:]
	}
	addr.header = DupBuffer(header)
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
	var alive utils.AtomicFlag
	var timeout int
	if c != nil && c.Timeout > 0 {
		timeout = c.Timeout
	}
	f := func(dst, src net.Conn, die chan bool, buf []byte) {
		defer close(die)
		defer utils.PutBuf(buf)
		var n int
		var err error
		for err == nil {
			if timeout > 0 {
				src.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
			}
			n, err = src.Read(buf)
			if n > 0 || err == nil {
				if timeout > 0 {
					dst.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
					alive.Set(true)
				}
				_, err = dst.Write(buf[:n])
			}
			if err != nil {
				ne, ok := err.(net.Error)
				if ok && ne.Timeout() {
					if alive.Test() {
						alive.Set(false)
						err = nil
					}
				}
			}
		}
	}
	go f(c1, c2, c1die, utils.GetBuf(buffersize))
	go f(c2, c1, c2die, utils.GetBuf(buffersize))
	select {
	case <-c1die:
	case <-c2die:
	}
	return
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
	case *SsConn:
		c = i.Conn
	case *DebugConn:
		c = i.Conn
	case *RemainConn:
		c = i.Conn
	case *LimitConn:
		c = i.Conn
	case *statConn:
		c = i.Conn
	}
	return
}

func GetNetTCPConn(conn net.Conn) (c *net.TCPConn, err error) {
	t, err := GetTCPConn(conn)
	if err != nil {
		return
	}
	ut, ok := t.Conn.(*utils.UtilsConn)
	if !ok {
		err = fmt.Errorf("unexpect conn with type %T", conn)
		return
	}
	c, ok = ut.GetTCPConn()
	if !ok {
		err = fmt.Errorf("unexpect conn with type %T", conn)
		return
	}
	return
}

func GetTCPConn(conn net.Conn) (c *TCPConn, err error) {
	c, ok := conn.(*TCPConn)
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
		c = newTCPConn2(conn, nil)
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
	String() string
}

type SockAddr struct {
	header []byte
	nop    bool
	ts     bool
}

func (s *SockAddr) String() string {
	return net.JoinHostPort(s.Host(), s.Port())
}

func (s *SockAddr) Host() string {
	b := s.header
	switch b[0] {
	default:
		return utils.SliceToString(b[2 : 2+int(b[1])])
	case typeIPv4:
		return net.IP(b[1 : lenIPv4+1]).String()
	case typeIPv6:
		return net.IP(b[1 : lenIPv6+1]).String()
	case typeMux:
		return muxhost
	}
}

func (s *SockAddr) Port() string {
	return strconv.Itoa(s.PortNum())
}

func (s *SockAddr) PortNum() int {
	var off int
	b := s.header
	switch b[0] {
	default:
		off = int(b[1]) + 2
	case typeIPv4:
		off = lenIPv4 + 1
	case typeIPv6:
		off = lenIPv6 + 1
	case typeMux:
		return muxport
	}
	return int(binary.BigEndian.Uint16(b[off:]))
}

func (s *SockAddr) Header() []byte {
	return s.header
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

func (d *DstAddr) String() string {
	return net.JoinHostPort(d.Host(), d.Port())
}

func (d *DstAddr) Header() []byte {
	if d.header == nil {
		port, _ := strconv.Atoi(d.port)
		d.header, _ = GetHeader(d.host, port)
	}
	return d.header
}

func SliceCopy(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func DialTCP(address string, cfg *cfg) (*TCPConn, error) {
	raddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}
	tconn, err := utils.DialTCP("tcp", nil, raddr)
	if err != nil {
		return nil, err
	}
	return newTCPConn(tconn, cfg), nil
}

func DialTCPConn(address string, cfg *cfg) (Conn, error) {
	conn, err := DialTCP(address, cfg)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type ivChecker struct {
	ivs1    map[string]bool
	ivs2    map[string]bool
	expires time.Time
	lock    sync.Mutex
	once    sync.Once
}

func (c *ivChecker) check(iv string) bool {
	c.once.Do(func() {
		c.ivs1 = make(map[string]bool)
		c.ivs2 = make(map[string]bool)
		c.expires = time.Now().Add(time.Second * 10)
	})
	c.lock.Lock()
	defer c.lock.Unlock()
	if time.Now().After(c.expires) {
		c.expires = time.Now().Add(time.Second * 10)
		c.ivs1 = c.ivs2
		c.ivs2 = make(map[string]bool)
	}
	_, ok := c.ivs1[iv]
	if ok {
		return false
	}
	_, ok = c.ivs2[iv]
	if ok {
		return false
	}
	c.ivs2[iv] = true
	return true
}

func newAutoProxy() *autoProxy {
	return &autoProxy{
		byPassDmRoot: utils.NewDomainRoot(),
		proxyDmRoot:  utils.NewDomainRoot(),
	}
}

type autoProxy struct {
	byPassDmRoot *utils.DomainRoot
	proxyDmRoot  *utils.DomainRoot
	lock         sync.RWMutex
}

func (ap *autoProxy) loadByPassList(bypassList string) (err error) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	f, err := os.Open(bypassList)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ap.byPassDmRoot.Put(scanner.Text())
	}
	err = scanner.Err()
	return
}

func (ap *autoProxy) loadPorxyList(proxyList string) (err error) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	f, err := os.Open(proxyList)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		ap.proxyDmRoot.Put(scanner.Text())
	}
	err = scanner.Err()
	return
}

func (ap *autoProxy) getByPassHosts() []string {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	hosts := ap.byPassDmRoot.Get()
	return hosts
}

func (ap *autoProxy) getProxyHosts() []string {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	hosts := ap.proxyDmRoot.Get()
	return hosts
}

func (ap *autoProxy) markHostNeedProxy(host string) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	ap.proxyDmRoot.Put(host)
}

func (ap *autoProxy) markHostByPass(host string) {
	ap.lock.Lock()
	defer ap.lock.Unlock()
	ap.byPassDmRoot.Put(host)
}

func (ap *autoProxy) checkIfProxy(host string) bool {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	return ap.proxyDmRoot.Test(host)
}

func (ap *autoProxy) checkIfByPass(host string) bool {
	ap.lock.RLock()
	defer ap.lock.RUnlock()
	return ap.byPassDmRoot.Test(host)
}

type chnRouteList struct {
	tree *utils.IPTree
	lock sync.RWMutex
}

func (route *chnRouteList) load(path string) (err error) {
	route.lock.Lock()
	defer route.lock.Unlock()
	if route.tree == nil {
		route.tree = utils.NewIPTree()
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		route.tree.Insert(scanner.Text())
	}
	err = scanner.Err()
	return
}

func (route *chnRouteList) testIP(ip net.IP) bool {
	route.lock.RLock()
	defer route.lock.RUnlock()
	return route.tree.TestIP(ip)
}

type bytesFilter interface {
	Close() error
	TestAndAdd([]byte) bool
}

type nullFilterImpl struct{}

func newNullFilter() bytesFilter {
	return &nullFilterImpl{}
}

func (r *nullFilterImpl) Close() error { return nil }

func (r *nullFilterImpl) TestAndAdd(_ []byte) bool { return false }
