package ss

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ccsexyz/shadowsocks-go/crypto"
	"github.com/ccsexyz/shadowsocks-go/domain"
	"github.com/ccsexyz/shadowsocks-go/internal/utils"
)

const (
	defaultMethod          = domain.DefaultMethod
	defaultPassword        = domain.DefaultPassword
	defaultTimeout         = domain.DefaultTimeout
	buffersize             = domain.BufferSize
	httpbuffersize         = domain.HTTPBufferSize
	verSocks4Resp          = domain.VerSocks4Resp
	verSocks4              = domain.VerSocks4
	verSocks5              = domain.VerSocks5
	verSocks6              = domain.VerSocks6
	cmdConnect             = domain.CmdConnect
	cmdUDP                 = domain.CmdUDP
	cmdSocks4OK            = domain.CmdSocks4OK
	typeIPv4               = domain.TypeIPv4
	typeDm                 = domain.TypeDm
	typeIPv6               = domain.TypeIPv6
	typeMux                = domain.TypeMux
	typeTs                 = domain.TypeTs  // timestamp
	typeNop                = domain.TypeNop // [nop 1 byte] [noplen 1 byte (< 128)] [zero data, noplen byte]
	lenIPv4                = domain.LenIPv4
	lenIPv6                = domain.LenIPv6
	lenTs                  = domain.LenTs
	muxaddr                = domain.MuxAddr
	muxhost                = domain.MuxHost
	muxport                = domain.MuxPort
	defaultObfsHost        = domain.DefaultObfsHost
	defaultFilterCapacity  = domain.DefaultFilterCapacity
	defaultFilterFalseRate = domain.DefaultFilterFalseRate
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
	errInvalidHeader        = fmt.Errorf("invalid header")
	errDuplicatedInitVector = fmt.Errorf("receive duplicated iv")
)

func ParseAddr(b []byte) (*domain.SockAddr, []byte, error) {
	return domain.ParseAddr(b)
}

func DupBuffer(b []byte) []byte {
	return domain.DupBuffer(b)
}

func IsTimeoutError(err error) bool {
	return domain.IsTimeoutError(err)
}

func CheckConn(conn net.Conn) bool {
	return domain.CheckConn(conn)
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
	iv   []byte
	data []byte
	addr *SockAddr
	dec  crypto.CipherStream
	cb   crypto.CipherBlock
	chs  *Config

	cliCipher *crypto.TcpCipher2022
	cliSalt   []byte
}

func ParseAddrWithMultipleBackendsForUDP(b []byte, configs []*Config) (*parseContext, error) {
	ctxs := make([]*parseContext, 0, len(configs))

	b2 := make([]byte, len(b))

	for _, cfg := range configs {
		cb, err := crypto.NewCipherBlock(cfg.Method, cfg.Password)
		if err != nil {
			continue
		}

		p, iv, err := cb.Decrypt(b2, b)
		if err != nil {
			continue
		}

		addr, data, err := ParseAddr(p)
		if err != nil {
			continue
		}

		ctx := new(parseContext)
		ctx.data = data
		ctx.addr = addr
		ctx.cb = cb
		ctx.chs = cfg
		ctx.iv = iv

		ctxs = append(ctxs, ctx)
	}

	if len(ctxs) == 0 {
		return nil, errInvalidHeader
	}

	return ctxs[0], nil
}

func ParseAddrWithMultipleBackends(b []byte, configs []*Config) (*parseContext, error) {
	ctxs := make([]*parseContext, 0, len(configs))
	var errs []string

	for i, cfg := range configs {
		if crypto.IsAEAD2022(cfg.Method) {
			ctx, err := tryDecodeAead2022(b, cfg)
			if err != nil {
				errs = append(errs, fmt.Sprintf("backend[%d] 2022 %s: %v", i, cfg.Method, err))
				continue
			}
			ctxs = append(ctxs, ctx)
			continue
		}
		dec, err := crypto.NewDecrypter(cfg.Method, cfg.Password)
		if err != nil {
			errs = append(errs, fmt.Sprintf("backend[%d] %s: NewDecrypter: %v", i, cfg.Method, err))
			continue
		}

		_, err = dec.Write(b)
		if err != nil {
			errs = append(errs, fmt.Sprintf("backend[%d] %s: dec.Write: %v", i, cfg.Method, err))
			continue
		}

		buf, err := io.ReadAll(dec)
		if err != nil {
			errs = append(errs, fmt.Sprintf("backend[%d] %s: dec.Read: %v", i, cfg.Method, err))
			continue
		}

		addr, data, err := ParseAddr(buf)
		if err != nil {
			errs = append(errs, fmt.Sprintf("backend[%d] %s: ParseAddr: %v (decrypted=%d bytes: %x)", i, cfg.Method, err, len(buf), safeHeadHex(buf, 64)))
			continue
		}

		ctx := new(parseContext)
		ctx.data = data
		ctx.addr = addr
		ctx.dec = dec
		ctx.chs = cfg

		ctxs = append(ctxs, ctx)
	}

	if len(ctxs) == 0 {
		detail := strings.Join(errs, "; ")
		return nil, fmt.Errorf("invalid header: all %d backend(s) failed: [%s] (input=%d bytes: %x)", len(configs), detail, len(b), safeHeadHex(b, 64))
	}

	return ctxs[0], nil
}

func safeHeadHex(b []byte, n int) []byte {
	if len(b) > n {
		return []byte(fmt.Sprintf("%x", b[:n]))
	}
	return []byte(fmt.Sprintf("%x", b))
}

// IsTimeoutError checks if the error is a timeout error.

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
			if err != nil {
				c.LogD("pipe read error:", err, "from", src.RemoteAddr(), "to", src.LocalAddr())
			}
			if n > 0 || err == nil {
				if timeout > 0 {
					dst.SetWriteDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
					alive.Set(true)
				}
				_, err = dst.Write(buf[:n])
				if err != nil {
					c.LogD("pipe write error:", err, "from", src.LocalAddr(), "to", dst.RemoteAddr())
				}
			}
			if err != nil && IsTimeoutError(err) && alive.Test() {
				alive.Set(false)
				c.LogD("pipe read error:", err, "from", src.RemoteAddr(), "to", src.LocalAddr())
				err = nil
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
	u, ok := conn.(Unwrapper)
	if !ok {
		return nil, fmt.Errorf("unexpected conn with type %T", conn)
	}
	return u.Unwrap(), nil
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

func GetConn(conn net.Conn) (c Conn) {
	var ok bool
	c, ok = conn.(Conn)
	if !ok {
		c = newTCPConn2(conn, nil)
	}
	return
}

// CheckConn Check the Conn whether is still alive

type Addr = domain.Addr
type SockAddr = domain.SockAddr
type DstAddr = domain.DstAddr

func checkAddrType(address string) (isDomain, isV4 bool, host string, port int) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return
	}
	port, err = strconv.Atoi(portStr)
	if err != nil {
		return
	}

	ip := net.ParseIP(host)
	if ip == nil {
		isDomain = true
		return
	}

	isV4 = ip.To4() != nil
	return
}

func isAddrDualStack(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		ips, err := net.LookupIP(host)
		if err == nil {
			var hasV4, hasV6 bool

			for _, ip := range ips {
				if ip.To4() != nil {
					hasV4 = true
				} else if ip.To16() != nil {
					hasV6 = true
				}

				if hasV4 && hasV6 {
					return true
				}
			}
		}
	}

	return false
}

func DialTCP(address string, cfg *cfg) (*TCPConn, error) {
	var protocol string
	dialCtx := context.Background()

	if cfg.NoIPv4 {
		protocol = "tcp6"
	} else if cfg.NoIPv6 {
		protocol = "tcp4"
	} else if cfg.PreferIPv4 && isAddrDualStack(address) {
		protocol = "tcp4"
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		dialCtx = ctx
	} else {
		protocol = "tcp"
	}

	tconn, err := utils.DialTCP(protocol, address, dialCtx)

	if err != nil && protocol == "tcp4" && !cfg.NoIPv6 && cfg.PreferIPv4 && isAddrDualStack(address) {
		tconn, err = utils.DialTCP("tcp", address, context.Background())
	}
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
	ivs3    map[string]bool
	expires time.Time
	lock    sync.Mutex
	once    sync.Once
}

func (c *ivChecker) check(iv string) bool {
	c.once.Do(func() {
		c.ivs1 = make(map[string]bool)
		c.ivs2 = make(map[string]bool)
		c.ivs3 = make(map[string]bool)
		c.expires = time.Now().Add(time.Second * time.Duration(domain.IvExpireSecond) * 3)
	})
	c.lock.Lock()
	defer c.lock.Unlock()
	if time.Now().After(c.expires) {
		c.expires = time.Now().Add(time.Second * time.Duration(domain.IvExpireSecond) * 3)
		c.ivs1 = c.ivs2
		c.ivs2 = c.ivs3
		c.ivs3 = make(map[string]bool)
	}
	_, ok := c.ivs1[iv]
	if ok {
		return false
	}
	_, ok = c.ivs2[iv]
	if ok {
		return false
	}
	_, ok = c.ivs3[iv]
	if ok {
		return false
	}
	c.ivs3[iv] = true
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
